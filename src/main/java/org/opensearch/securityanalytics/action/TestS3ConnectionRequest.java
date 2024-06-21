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
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.securityanalytics.commons.connector.model.S3ConnectorConfig;

import java.io.IOException;

public class TestS3ConnectionRequest extends ActionRequest implements ToXContentObject {
    public static final String BUCKET_NAME_FIELD = "bucket_name";
    public static final String OBJECT_KEY_FIELD = "object_key";
    public static final String REGION_FIELD = "region";
    public static final String ROLE_ARN_FIELD = "role_arn";

    private final String bucketName;
    private final String objectKey;
    private final String region;
    private final String roleArn;

    public TestS3ConnectionRequest(String bucketName, String objectKey, String region, String roleArn) {
        super();
        this.bucketName = bucketName;
        this.objectKey = objectKey;
        this.region = region;
        this.roleArn = roleArn;
    }

    public TestS3ConnectionRequest(StreamInput sin) throws IOException {
        this(
                sin.readString(), // bucketName
                sin.readString(), // objectKey
                sin.readString(), // region
                sin.readString() // roleArn
        );
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(bucketName);
        out.writeString(objectKey);
        out.writeString(region);
        out.writeString(roleArn);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (bucketName == null || bucketName.isEmpty()) {
            validationException = ValidateActions.addValidationError("Must provide bucket name.", validationException);
        }
        if (objectKey == null || objectKey.isEmpty()) {
            validationException = ValidateActions.addValidationError("Must provide object key.", validationException);
        }
        if (region == null || region.isEmpty()) {
            validationException = ValidateActions.addValidationError("Must provide region.", validationException);
        }
        if (roleArn == null || roleArn.isEmpty()) {
            validationException = ValidateActions.addValidationError("Must provide role ARN.", validationException);
        }
        return validationException;
    }

    public static TestS3ConnectionRequest parse(XContentParser xcp) throws IOException {
        String bucketName = "";
        String objectKey = "";
        String region = "";
        String roleArn = "";

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case BUCKET_NAME_FIELD:
                    bucketName = xcp.text();
                    break;
                case OBJECT_KEY_FIELD:
                    objectKey = xcp.text();
                    break;
                case REGION_FIELD:
                    region = xcp.text();
                    break;
                case ROLE_ARN_FIELD:
                    roleArn = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        return new TestS3ConnectionRequest(bucketName, objectKey, region, roleArn);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(BUCKET_NAME_FIELD, bucketName)
                .field(OBJECT_KEY_FIELD, objectKey)
                .field(REGION_FIELD, region)
                .field(ROLE_ARN_FIELD, roleArn)
                .endObject();
    }

    public S3ConnectorConfig getS3ConnectorConfig() {
        return new S3ConnectorConfig(bucketName, objectKey, region, roleArn);
    }
}
