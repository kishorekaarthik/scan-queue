package dev.scanqueue.storage;

import io.minio.BucketExistsArgs;
import io.minio.GetObjectArgs;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.errors.ErrorResponseException;
import org.springframework.stereotype.Component;

import java.io.InputStream;

/** Thin wrapper over MinIO so the rest of the code never sees the SDK's checked exceptions. */
@Component
public class ObjectStore {

    private final MinioClient client;
    private final String bucket;

    public ObjectStore(StorageProperties props) {
        this.client = MinioClient.builder()
                .endpoint(props.endpoint())
                .credentials(props.accessKey(), props.secretKey())
                .build();
        this.bucket = props.bucket();
    }

    /** Idempotent: safe for every instance to call on startup. */
    public void ensureBucket() {
        try {
            if (!client.bucketExists(BucketExistsArgs.builder().bucket(bucket).build())) {
                try {
                    client.makeBucket(MakeBucketArgs.builder().bucket(bucket).build());
                } catch (ErrorResponseException e) {
                    // Another instance created it between our check and our create.
                    String code = e.errorResponse().code();
                    if (!"BucketAlreadyOwnedByYou".equals(code) && !"BucketAlreadyExists".equals(code)) {
                        throw e;
                    }
                }
            }
        } catch (Exception e) {
            throw new StorageException("could not ensure bucket " + bucket, e);
        }
    }

    public void put(String key, InputStream data, long size, String contentType) {
        try {
            client.putObject(PutObjectArgs.builder()
                    .bucket(bucket)
                    .object(key)
                    .stream(data, size, -1)
                    .contentType(contentType == null ? "application/octet-stream" : contentType)
                    .build());
        } catch (Exception e) {
            throw new StorageException("could not store " + key, e);
        }
    }

    /** Caller must close the stream. */
    public InputStream get(String key) {
        try {
            return client.getObject(GetObjectArgs.builder().bucket(bucket).object(key).build());
        } catch (Exception e) {
            throw new StorageException("could not read " + key, e);
        }
    }

    public static class StorageException extends RuntimeException {
        public StorageException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
