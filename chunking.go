package s3disk

import (
	"bytes"
	"context"
	"io"

	"github.com/restic/chunker"
)

type chunkData struct {
	Digest Digest
	Size   int64
	Data   []byte
}

func walkChunks(ctx context.Context, reader io.Reader, options ChunkingOptions, visit func(chunkData) error) error {
	options, err := options.normalized()
	if err != nil {
		return err
	}
	splitter := chunker.New(
		reader,
		chunker.Pol(options.Polynomial),
		chunker.WithBoundaries(uint(options.MinSize), uint(options.MaxSize)),
		chunker.WithAverageBits(options.averageBits()),
	)
	var buffer []byte
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk, err := splitter.Next(buffer)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		buffer = chunk.Data[:0]
		piece := chunkData{
			Digest: digestObject("chunk", chunk.Data),
			Size:   int64(len(chunk.Data)),
			Data:   chunk.Data,
		}
		if err := visit(piece); err != nil {
			return err
		}
	}
}

func chunkBytes(ctx context.Context, data []byte, options ChunkingOptions) ([]chunkData, error) {
	var result []chunkData
	err := walkChunks(ctx, bytes.NewReader(data), options, func(chunk chunkData) error {
		result = append(result, chunkData{Digest: chunk.Digest, Size: chunk.Size})
		return nil
	})
	return result, err
}
