package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/vibe-agi/s3disk/presignedshare"
	"github.com/vibe-agi/s3disk/s3store"
)

func runDoctor(ctx context.Context, options DoctorOptions, output io.Writer) error {
	if ctx == nil {
		return fmt.Errorf("s3disk s3 doctor: context is required")
	}
	if output == nil {
		return fmt.Errorf("s3disk s3 doctor: output is required")
	}
	tlsRootCAPEM, err := readBoundedFile(options.TLSCAFile, presignedshare.MaximumTLSRootCAPEMBytes)
	if err != nil {
		return fmt.Errorf("s3disk s3 doctor: read TLS CA: %w", err)
	}
	httpClient, err := s3HTTPClient(tlsRootCAPEM)
	if err != nil {
		return fmt.Errorf("s3disk s3 doctor: TLS CA: %w", err)
	}
	store, err := s3store.New(ctx, s3store.Config{
		Bucket:                options.Bucket,
		Region:                options.Region,
		Endpoint:              options.Endpoint,
		ExpectedBucketOwner:   options.ExpectedBucketOwner,
		UsePathStyle:          options.UsePathStyle,
		AllowInsecureEndpoint: options.AllowInsecureEndpoint,
		HTTPClient:            httpClient,
	})
	if err != nil {
		return fmt.Errorf("s3disk s3 doctor: configure store: %w", err)
	}
	report, probeErr := store.ProbePresignedGetCompatibilityWithOptions(ctx, s3store.PresignedGetCompatibilityProbeOptions{
		ObjectKeyPrefix:                  options.Prefix,
		TotalTimeout:                     options.TotalTimeout,
		CapabilityLifetime:               options.CapabilityLifetime,
		CleanupTimeout:                   options.CleanupTimeout,
		TLSRootCAPEM:                     tlsRootCAPEM,
		DangerouslyAllowSystemTrustStore: options.DangerouslyAllowSystemTrust,
	})
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("s3disk s3 doctor: write report: %w", err)
	}
	if probeErr != nil {
		return probeErr
	}
	if !report.Compatible || !report.Complete || report.Status != s3store.PresignedGetCompatibilityPassed {
		return fmt.Errorf("s3disk s3 doctor: provider did not produce complete compatible evidence")
	}
	return nil
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	if maximum < 1 {
		return nil, fmt.Errorf("invalid size bound")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file is not regular")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return data, nil
}
