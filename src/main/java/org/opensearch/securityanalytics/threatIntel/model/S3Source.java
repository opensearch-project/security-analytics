package org.opensearch.securityanalytics.threatIntel.model;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;

public class S3Source extends Source implements Writeable, ToXContent {

    public static final String BUCKET_NAME_FIELD = "bucket_name";
    public static final String OBJECT_KEY_FIELD = "object_key";
    public static final String REGION_FIELD = "region";
    public static final String ROLE_ARN_FIELD = "role_arn";
    private String bucketName;
    private String objectKey;
    private String region;
    private String roleArn;

    public S3Source(String bucketName, String objectKey, String region, String roleArn) {
        this.bucketName = bucketName;
        this.objectKey = objectKey;
        this.region = region;
        this.roleArn = roleArn;
    }

    public S3Source(StreamInput sin) throws IOException {
        this (
                sin.readString(), // bucket name
                sin.readString(), // object key
                sin.readString(), // region
                sin.readString() // role arn
        );
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(bucketName);
        out.writeString(objectKey);
        out.writeString(region);
        out.writeString(roleArn);
    }

    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        builder.startObject()
                .field(S3_FIELD);
        builder.startObject()
                .field(BUCKET_NAME_FIELD, bucketName)
                .field(OBJECT_KEY_FIELD, objectKey)
                .field(REGION_FIELD, region)
                .field(ROLE_ARN_FIELD, roleArn);
        builder.endObject();
        builder.endObject();
        return builder;
    }

    @Override
    String name() {
        return S3_FIELD;
    }

    public static S3Source parse(XContentParser xcp) throws IOException {
        String bucketName = null;
        String objectKey = null;
        String region = null;
        String roleArn = null;

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
                    break;
            }
        }
        return new S3Source(
                bucketName,
                objectKey,
                region,
                roleArn
        );
    }

    public String getBucketName() {
        return bucketName;
    }

    public void setBucketName(String bucketName) {
        this.bucketName = bucketName;
    }

    public String getObjectKey() {
        return objectKey;
    }

    public void setObjectKey(String objectKey) {
        this.objectKey = objectKey;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getRoleArn() {
        return roleArn;
    }

    public void setRoleArn(String roleArn) {
        this.roleArn = roleArn;
    }
}
