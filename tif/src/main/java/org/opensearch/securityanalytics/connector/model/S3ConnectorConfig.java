/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.connector.model;

import org.opensearch.securityanalytics.model.IOCSchema;

public class S3ConnectorConfig {
    private final String bucketName;
    private final String objectKey;
    private final String region;
    private final String roleArn;
    private final IOCSchema iocSchema;
    private final InputCodecSchema inputCodecSchema;
    private final String feedId;

    public S3ConnectorConfig(final String bucketName, final String objectKey, final String region,
                             final String roleArn, final IOCSchema iocSchema, final InputCodecSchema inputCodecSchema,
                             final String feedId) {
        this.bucketName = bucketName;
        this.objectKey = objectKey;
        this.region = region;
        this.roleArn = roleArn;
        this.iocSchema = iocSchema;
        this.inputCodecSchema = inputCodecSchema;
        this.feedId = feedId;
    }

    public String getBucketName() {
        return bucketName;
    }

    public String getObjectKey() {
        return objectKey;
    }

    public String getRegion() {
        return region;
    }

    public String getRoleArn() {
        return roleArn;
    }

    public IOCSchema getIocSchema() {
        return iocSchema;
    }

    public InputCodecSchema getInputCodecSchema() {
        return inputCodecSchema;
    }

    public String getFeedId() {
        return feedId;
    }
}
