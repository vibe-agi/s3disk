//go:build scale

package s3disk_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/vibe-agi/s3disk"
	"github.com/vibe-agi/s3disk/memstore"
	s3webdav "github.com/vibe-agi/s3disk/webdav"
)

const (
	defaultScaleFiles       = 2_000
	defaultScaleFileBytes   = 1_024
	defaultScaleGenerations = 3
	defaultScaleReaders     = 8
	maximumScaleSourceBytes = int64(512 << 20)
)

type scaleProfileEvidence struct {
	Files                int    `json:"files"`
	FileBytes            int    `json:"file_bytes"`
	Generations          int    `json:"generations"`
	ConcurrentReaders    int    `json:"concurrent_readers"`
	GOOS                 string `json:"goos"`
	GOARCH               string `json:"goarch"`
	InitialPublishMillis int64  `json:"initial_publish_millis"`
	UpdatePublishMillis  int64  `json:"update_publish_millis"`
	RefreshMillis        int64  `json:"refresh_millis"`
	ReadMillis           int64  `json:"read_millis"`
	WebDAVReadMillis     int64  `json:"webdav_read_millis"`
	HeapAllocBytes       uint64 `json:"heap_alloc_bytes"`
	HeapInuseBytes       uint64 `json:"heap_inuse_bytes"`
	Goroutines           int    `json:"goroutines"`
}

// TestWorkspaceScaleProfile is an opt-in, deterministic scale gate. It
// exercises complete workspace scans, immutable publication, refresh, and
// concurrent lazy reads while emitting one machine-readable evidence record.
// Run it through scripts/test-scale.sh so a missing build tag or accidental
// skip cannot produce a green result.
func TestWorkspaceScaleProfile(t *testing.T) {
	if os.Getenv("S3DISK_RUN_SCALE") != "1" {
		t.Skip("set S3DISK_RUN_SCALE=1 or use scripts/test-scale.sh")
	}
	files := scaleEnvInt(t, "S3DISK_SCALE_FILES", defaultScaleFiles, 1, 100_000)
	fileBytes := scaleEnvInt(t, "S3DISK_SCALE_FILE_BYTES", defaultScaleFileBytes, 1, 1<<20)
	generations := scaleEnvInt(t, "S3DISK_SCALE_GENERATIONS", defaultScaleGenerations, 1, 100)
	readers := scaleEnvInt(t, "S3DISK_SCALE_READERS", defaultScaleReaders, 1, 128)
	if int64(files) > maximumScaleSourceBytes/int64(fileBytes) {
		t.Fatalf("scale source exceeds %d bytes", maximumScaleSourceBytes)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	source := t.TempDir()
	paths := make([]string, files)
	directoryCount := files
	if directoryCount > 64 {
		directoryCount = 64
	}
	for index := range files {
		relative := filepath.Join(
			fmt.Sprintf("dir-%03d", index%directoryCount),
			fmt.Sprintf("file-%06d.bin", index),
		)
		absolute := filepath.Join(source, relative)
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, scalePayload(index, 1, fileBytes), 0o600); err != nil {
			t.Fatal(err)
		}
		paths[index] = filepath.ToSlash(relative)
	}

	repository, err := s3disk.NewRepository(memstore.New(), "scale-profile")
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := s3disk.NewPublisher(repository, s3disk.PublisherOptions{
		DangerouslyAllowUncommissionedRepository: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	initial, err := publisher.Publish(ctx, source, "main")
	initialPublish := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	watermarks, err := s3disk.NewFileWatermarkStore(filepath.Join(t.TempDir(), "watermark.json"))
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := s3disk.NewConsumer(repository, "main", s3disk.ConsumerOptions{
		Watermarks: watermarks, RequirePersistentWatermark: true,
		Symlinks: s3disk.SymlinkRejectExternal,
	})
	if err != nil {
		t.Fatal(err)
	}
	webDAVHandler, err := s3webdav.NewHandler(consumer)
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	refreshed, err := webDAVHandler.Refresh(ctx)
	refreshDuration := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Generation != initial.Generation {
		t.Fatalf("initial refresh generation = %d, want %d", refreshed.Generation, initial.Generation)
	}
	started = time.Now()
	if err := readScaleWorkspace(ctx, consumer, paths, readers); err != nil {
		t.Fatal(err)
	}
	readDuration := time.Since(started)
	server := httptest.NewServer(webDAVHandler)
	defer server.Close()
	expectedGenerations := make([]int, len(paths))
	for index := range expectedGenerations {
		expectedGenerations[index] = 1
	}
	started = time.Now()
	if err := readWebDAVScaleWorkspace(ctx, server.Client(), server.URL, paths,
		expectedGenerations, fileBytes, readers); err != nil {
		t.Fatal(err)
	}
	webDAVReadDuration := time.Since(started)

	var updatePublishDuration time.Duration
	for generation := 2; generation <= generations; generation++ {
		index := (generation - 2) % len(paths)
		absolute := filepath.Join(source, filepath.FromSlash(paths[index]))
		if err := os.WriteFile(absolute, scalePayload(index, generation, fileBytes), 0o600); err != nil {
			t.Fatal(err)
		}
		started = time.Now()
		snapshot, err := publisher.Publish(ctx, source, "main")
		updatePublishDuration += time.Since(started)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Generation != uint64(generation) {
			t.Fatalf("published generation = %d, want %d", snapshot.Generation, generation)
		}
		expectedGenerations[index] = generation
		started = time.Now()
		refreshed, err := webDAVHandler.Refresh(ctx)
		refreshDuration += time.Since(started)
		if err != nil {
			t.Fatal(err)
		}
		if refreshed.Generation != snapshot.Generation {
			t.Fatalf("refresh generation = %d, want %d", refreshed.Generation, snapshot.Generation)
		}
		started = time.Now()
		if err := readScaleWorkspace(ctx, consumer, paths, readers); err != nil {
			t.Fatal(err)
		}
		readDuration += time.Since(started)
		started = time.Now()
		if err := readWebDAVScaleWorkspace(ctx, server.Client(), server.URL, paths,
			expectedGenerations, fileBytes, readers); err != nil {
			t.Fatal(err)
		}
		webDAVReadDuration += time.Since(started)
	}

	runtime.GC()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	// Keep the populated repository and consumer reachable through the sample;
	// otherwise compiler liveness may make a retained-memory regression vanish
	// from this evidence even though the scale run still owns the objects.
	runtime.KeepAlive(consumer)
	runtime.KeepAlive(repository)
	evidence := scaleProfileEvidence{
		Files: files, FileBytes: fileBytes, Generations: generations,
		ConcurrentReaders: readers, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		InitialPublishMillis: initialPublish.Milliseconds(),
		UpdatePublishMillis:  updatePublishDuration.Milliseconds(),
		RefreshMillis:        refreshDuration.Milliseconds(), ReadMillis: readDuration.Milliseconds(),
		WebDAVReadMillis: webDAVReadDuration.Milliseconds(),
		HeapAllocBytes:   memory.HeapAlloc, HeapInuseBytes: memory.HeapInuse,
		Goroutines: runtime.NumGoroutine(),
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("S3DISK_SCALE_EVIDENCE=%s", encoded)
}

type webDAVScaleRead struct {
	index      int
	path       string
	generation int
}

func readWebDAVScaleWorkspace(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	paths []string,
	expectedGenerations []int,
	fileBytes int,
	readers int,
) error {
	if len(paths) != len(expectedGenerations) {
		return errors.New("WebDAV scale expectations do not match paths")
	}
	if err := readWebDAVScaleDirectories(ctx, client, baseURL, paths); err != nil {
		return err
	}
	readContext, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan webDAVScaleRead)
	errorsFound := make(chan error, 1)
	var wait sync.WaitGroup
	for range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for item := range work {
				request, err := http.NewRequestWithContext(readContext, http.MethodGet,
					baseURL+"/"+item.path, nil)
				if err == nil {
					var response *http.Response
					response, err = client.Do(request)
					if err == nil {
						contents, readErr := io.ReadAll(io.LimitReader(response.Body, int64(fileBytes)+1))
						closeErr := response.Body.Close()
						if readErr != nil {
							err = readErr
						} else if closeErr != nil {
							err = closeErr
						} else if response.StatusCode != http.StatusOK {
							err = fmt.Errorf("GET status %d", response.StatusCode)
						} else if !bytes.Equal(contents, scalePayload(item.index, item.generation, fileBytes)) {
							err = errors.New("GET returned unexpected contents")
						}
					}
				}
				if err != nil {
					select {
					case errorsFound <- fmt.Errorf("read WebDAV scale file %q: %w", item.path, err):
						cancel()
					default:
					}
					return
				}
			}
		}()
	}
	for index, value := range paths {
		select {
		case work <- webDAVScaleRead{index: index, path: value, generation: expectedGenerations[index]}:
		case <-readContext.Done():
		}
		if readContext.Err() != nil {
			break
		}
	}
	close(work)
	wait.Wait()
	select {
	case err := <-errorsFound:
		return err
	default:
		return ctx.Err()
	}
}

func readWebDAVScaleDirectories(ctx context.Context, client *http.Client, baseURL string, paths []string) error {
	directorySet := map[string]struct{}{`/`: {}}
	for _, value := range paths {
		directorySet[path.Dir("/"+value)] = struct{}{}
	}
	directories := make([]string, 0, len(directorySet))
	for directory := range directorySet {
		directories = append(directories, directory)
	}
	sort.Strings(directories)
	for _, directory := range directories {
		request, err := http.NewRequestWithContext(ctx, "PROPFIND", baseURL+directory, nil)
		if err != nil {
			return err
		}
		request.Header.Set("Depth", "1")
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("PROPFIND scale directory %q: %w", directory, err)
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 16<<20))
		closeErr := response.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read PROPFIND scale directory %q: %w", directory, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close PROPFIND scale directory %q: %w", directory, closeErr)
		}
		if response.StatusCode != http.StatusMultiStatus {
			return fmt.Errorf("PROPFIND scale directory %q: status %d", directory, response.StatusCode)
		}
	}
	return nil
}

func scaleEnvInt(t *testing.T, name string, fallback, minimum, maximum int) int {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		t.Fatalf("%s must be an integer from %d through %d", name, minimum, maximum)
	}
	return value
}

func scalePayload(index, generation, size int) []byte {
	result := make([]byte, size)
	state := uint64(index+1)*0x9e3779b97f4a7c15 ^ uint64(generation)*0xbf58476d1ce4e5b9
	for offset := range result {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		result[offset] = byte(state)
	}
	return result
}

func readScaleWorkspace(ctx context.Context, consumer *s3disk.Consumer, paths []string, readers int) error {
	readContext, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan string)
	errorsFound := make(chan error, 1)
	var wait sync.WaitGroup
	for range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for value := range work {
				file, err := consumer.Open(readContext, value)
				if err == nil {
					data := make([]byte, file.Size())
					var count int
					count, err = file.ReadAtContext(readContext, data, 0)
					if err != nil && err != io.EOF {
						// Preserve the operation error below.
					} else if int64(count) != file.Size() {
						err = fmt.Errorf("read %q returned %d bytes, want %d", value, count, file.Size())
					} else {
						err = nil
					}
				}
				if err != nil {
					select {
					case errorsFound <- fmt.Errorf("read scale file %q: %w", value, err):
						cancel()
					default:
					}
					return
				}
			}
		}()
	}
	for _, value := range paths {
		select {
		case work <- value:
		case <-readContext.Done():
			break
		}
		if readContext.Err() != nil {
			break
		}
	}
	close(work)
	wait.Wait()
	select {
	case err := <-errorsFound:
		return err
	default:
		return ctx.Err()
	}
}
