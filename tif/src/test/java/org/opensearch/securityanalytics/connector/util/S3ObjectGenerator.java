package org.opensearch.securityanalytics.connector.util;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class S3ObjectGenerator {
    private final S3Client s3Client;
    private final String bucketName;

    public S3ObjectGenerator(final S3Client s3Client, final String bucketName) {
        this.s3Client = s3Client;
        this.bucketName = bucketName;
    }

    public void write(final int numberOfIOCs, final String key, final IOCGenerator iocGenerator) throws IOException {
        final File tempFile = File.createTempFile("s3-object-" + numberOfIOCs + "-", null);

        try {
            try (final OutputStream outputStream = new FileOutputStream(tempFile)) {

                iocGenerator.write(numberOfIOCs, outputStream);
                outputStream.flush();
            }

            final PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(key)
                    .build();
            s3Client.putObject(putObjectRequest, tempFile.toPath());
        } finally {
            tempFile.delete();
        }
    }
}
