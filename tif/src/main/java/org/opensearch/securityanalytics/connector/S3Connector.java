/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.connector;

import org.opensearch.securityanalytics.connector.codec.InputCodec;
import org.opensearch.securityanalytics.connector.factory.InputCodecFactory;
import org.opensearch.securityanalytics.connector.factory.S3ClientFactory;
import org.opensearch.securityanalytics.connector.model.S3ConnectorConfig;
import org.opensearch.securityanalytics.model.IOC;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import java.util.List;

public class S3Connector implements IOCConnector {
    private final S3ConnectorConfig s3ConnectorConfig;
    private final S3Client s3Client;
    private final InputCodec inputCodec;

    public S3Connector(final S3ConnectorConfig s3ConnectorConfig, final S3ClientFactory s3ClientFactory, final InputCodecFactory inputCodecFactory) {
        this.s3ConnectorConfig = s3ConnectorConfig;
        this.s3Client = s3ClientFactory.create(s3ConnectorConfig.getRoleArn(), s3ConnectorConfig.getRegion());
        this.inputCodec = inputCodecFactory.create(s3ConnectorConfig.getInputCodecSchema(), s3ConnectorConfig.getIocSchema());
    }

    @Override
    public List<IOC> loadIOCs() {
        final GetObjectRequest getObjectRequest = getObjectRequest();
        final ResponseInputStream<GetObjectResponse> response = s3Client.getObject(getObjectRequest);

        return inputCodec.parse(response);
    }

    private GetObjectRequest getObjectRequest() {
        return GetObjectRequest.builder()
                .bucket(s3ConnectorConfig.getBucketName())
                .key(s3ConnectorConfig.getObjectKey())
                .build();
    }
}
