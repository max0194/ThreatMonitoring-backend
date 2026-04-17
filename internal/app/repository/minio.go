package repository

import (
	"context"
	"fmt"
	"mime/multipart"
	"path/filepath"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/sirupsen/logrus"
)

type MinIOClient struct {
	Client *minio.Client
	Bucket string
}

func NewMinIOClient(endpoint, accessKey, secretKey, bucket string, useSSL bool) (*MinIOClient, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MinIO client: %w", err)
	}

	minioClient := &MinIOClient{
		Client: client,
		Bucket: bucket,
	}

	err = minioClient.ensureBucketExists(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to ensure bucket exists: %w", err)
	}

	return minioClient, nil
}

func (m *MinIOClient) ensureBucketExists(ctx context.Context) error {
	exists, err := m.Client.BucketExists(ctx, m.Bucket)
	if err != nil {
		return err
	}

	if !exists {
		err = m.Client.MakeBucket(ctx, m.Bucket, minio.MakeBucketOptions{})
		if err != nil {
			return err
		}
		logrus.Info("Bucket ", m.Bucket, " created successfully")
	}

	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {"AWS": "*"},
				"Action": ["s3:GetObject"],
				"Resource": ["arn:aws:s3:::` + m.Bucket + `/*"]
			}
		]
	}`

	err = m.Client.SetBucketPolicy(ctx, m.Bucket, policy)
	if err != nil {
		logrus.Warn("Failed to set bucket policy: ", err)
	}

	return nil
}

func (m *MinIOClient) UploadFile(ctx context.Context, file multipart.File, header *multipart.FileHeader, objectName string) (string, error) {
	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	_, err := m.Client.PutObject(ctx, m.Bucket, objectName, file, header.Size, minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload file: %w", err)
	}

	url := fmt.Sprintf("http://localhost:9000/%s/%s", m.Bucket, objectName)
	return url, nil
}

func GenerateObjectName(filename string) string {
	ext := filepath.Ext(filename)
	name := filename[:len(filename)-len(ext)]
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	return fmt.Sprintf("%s_%s%s", name, timestamp, ext)
}
