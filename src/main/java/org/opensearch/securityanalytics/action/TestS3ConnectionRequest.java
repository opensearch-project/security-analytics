/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.ValidateActions;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.securityanalytics.commons.connector.model.S3ConnectorConfig;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;

import java.io.IOException;

public class TestS3ConnectionRequest extends ActionRequest implements ToXContentObject {
    private final S3Source s3Source;

    public TestS3ConnectionRequest(S3Source s3Source) {
        super();
        this.s3Source = s3Source;
    }

    public TestS3ConnectionRequest(String bucketName, String objectKey, String region, String roleArn) {
        this(new S3Source(bucketName, objectKey, region, roleArn));
    }

    public TestS3ConnectionRequest(StreamInput sin) throws IOException {
        this(new S3Source(sin));
    }

    public void writeTo(StreamOutput out) throws IOException {
        s3Source.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (s3Source.getBucketName() == null || s3Source.getBucketName().isEmpty()) {
            validationException = ValidateActions.addValidationError("Must provide bucket name.", validationException);
        }
        if (s3Source.getObjectKey() == null || s3Source.getObjectKey().isEmpty()) {
            validationException = ValidateActions.addValidationError("Must provide object key.", validationException);
        }
        if (s3Source.getObjectKey() == null || s3Source.getObjectKey().isEmpty()) {
            validationException = ValidateActions.addValidationError("Must provide region.", validationException);
        }
        if (s3Source.getRoleArn() == null || s3Source.getRoleArn().isEmpty()) {
            validationException = ValidateActions.addValidationError("Must provide role ARN.", validationException);
        }
        return validationException;
    }

    public static TestS3ConnectionRequest parse(XContentParser xcp) throws IOException {
        return new TestS3ConnectionRequest(S3Source.parse(xcp));
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return s3Source.toXContent(builder, params);
    }

    public S3ConnectorConfig constructS3ConnectorConfig() {
        return new S3ConnectorConfig(
                s3Source.getBucketName(),
                s3Source.getObjectKey(),
                s3Source.getRegion(),
                s3Source.getRoleArn()
        );
    }

    public S3Source getS3Source() {
        return s3Source;
    }
}
