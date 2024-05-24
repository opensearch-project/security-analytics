package org.opensearch.securityanalytics.model.threatintel;

import org.apache.commons.lang3.StringUtils;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;

/**
 * IoC Match provides mapping of the IoC Value to the list of docs that contain the ioc in a given execution of IoC_Scan_job
 * It's the inverse of an IoC finding which maps a document to list of IoC's
 */
public class IocMatch implements Writeable, ToXContent {
    //TODO implement IoC_Match interface from security-analytics-commons
    public static final String ID_FIELD = "id";
    public static final String RELATED_DOC_IDS_FIELD = "related_doc_ids";
    public static final String FEED_IDS_FIELD = "feed_ids";
    public static final String IOC_SCAN_JOB_ID_FIELD = "ioc_scan_job_id";
    public static final String IOC_SCAN_JOB_NAME_FIELD = "ioc_scan_job_name";
    public static final String IOC_VALUE_FIELD = "ioc_value";
    public static final String IOC_TYPE_FIELD = "ioc_type";
    public static final String TIMESTAMP_FIELD = "timestamp";
    public static final String EXECUTION_ID_FIELD = "execution_id";

    private final String id;
    private final List<String> relatedDocIds;
    private final List<String> feedIds;
    private final String iocScanJobId;
    private final String iocScanJobName;
    private final String iocValue;
    private final String iocType;
    private final Instant timestamp;
    private final String executionId;

    public IocMatch(String id, List<String> relatedDocIds, List<String> feedIds, String iocScanJobId,
                    String iocScanJobName, String iocValue, String iocType, Instant timestamp, String executionId) {
        validateIoCMatch(id, iocScanJobId, iocScanJobName, iocValue, timestamp, executionId, relatedDocIds);
        this.id = id;
        this.relatedDocIds = relatedDocIds;
        this.feedIds = feedIds;
        this.iocScanJobId = iocScanJobId;
        this.iocScanJobName = iocScanJobName;
        this.iocValue = iocValue;
        this.iocType = iocType;
        this.timestamp = timestamp;
        this.executionId = executionId;
    }

    public IocMatch(StreamInput in) throws IOException {
        id = in.readString();
        relatedDocIds = in.readStringList();
        feedIds = in.readStringList();
        iocScanJobId = in.readString();
        iocScanJobName = in.readString();
        iocValue = in.readString();
        iocType = in.readString();
        timestamp = in.readInstant();
        executionId = in.readOptionalString();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeStringCollection(relatedDocIds);
        out.writeStringCollection(feedIds);
        out.writeString(iocScanJobId);
        out.writeString(iocScanJobName);
        out.writeString(iocValue);
        out.writeString(iocType);
        out.writeInstant(timestamp);
        out.writeOptionalString(executionId);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(ID_FIELD, id)
                .field(RELATED_DOC_IDS_FIELD, relatedDocIds)
                .field(FEED_IDS_FIELD, feedIds)
                .field(IOC_SCAN_JOB_ID_FIELD, iocScanJobId)
                .field(IOC_SCAN_JOB_NAME_FIELD, iocScanJobName)
                .field(IOC_VALUE_FIELD, iocValue)
                .field(IOC_TYPE_FIELD, iocType)
                .field(TIMESTAMP_FIELD, timestamp.toEpochMilli())
                .field(EXECUTION_ID_FIELD, executionId)
                .endObject();
        return builder;
    }

    public String getId() {
        return id;
    }

    public List<String> getRelatedDocIds() {
        return relatedDocIds;
    }

    public List<String> getFeedIds() {
        return feedIds;
    }

    public String getIocScanJobId() {
        return iocScanJobId;
    }

    public String getIocScanJobName() {
        return iocScanJobName;
    }

    public String getIocValue() {
        return iocValue;
    }

    public String getIocType() {
        return iocType;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getExecutionId() {
        return executionId;
    }

    public static IocMatch parse(XContentParser xcp) throws IOException {
        String id = null;
        List<String> relatedDocIds = new ArrayList<>();
        List<String> feedIds = new ArrayList<>();
        String iocScanJobId = null;
        String iocScanName = null;
        String iocValue = null;
        String iocType = null;
        Instant timestamp = null;
        String executionId = null;

        ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case ID_FIELD:
                    id = xcp.text();
                    break;
                case RELATED_DOC_IDS_FIELD:
                    ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        relatedDocIds.add(xcp.text());
                    }
                    break;
                case FEED_IDS_FIELD:
                    ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        feedIds.add(xcp.text());
                    }
                    break;
                case IOC_SCAN_JOB_ID_FIELD:
                    iocScanJobId = xcp.textOrNull();
                    break;
                case IOC_SCAN_JOB_NAME_FIELD:
                    iocScanName = xcp.textOrNull();
                    break;
                case IOC_VALUE_FIELD:
                    iocValue = xcp.textOrNull();
                    break;
                case IOC_TYPE_FIELD:
                    iocType = xcp.textOrNull();
                    break;
                case TIMESTAMP_FIELD:
                    try {
                        if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                            timestamp = null;
                        } else if (xcp.currentToken().isValue()) {
                            timestamp = Instant.ofEpochMilli(xcp.longValue());
                        } else {
                            XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                            timestamp = null;
                        }
                        break;
                    } catch (Exception e) {
                        throw new IllegalArgumentException("failed to parse timestamp in IoC Match object");
                    }
                case EXECUTION_ID_FIELD:
                    executionId = xcp.textOrNull();
                    break;
            }
        }

        return new IocMatch(id, relatedDocIds, feedIds, iocScanJobId, iocScanName, iocValue, iocType, timestamp, executionId);
    }

    public static IocMatch readFrom(StreamInput in) throws IOException {
        return new IocMatch(in);
    }


    private static void validateIoCMatch(String id, String iocScanJobId, String iocScanName, String iocValue, Instant timestamp, String executionId, List<String> relatedDocIds) {
        if (StringUtils.isBlank(id)) {
            throw new IllegalArgumentException("id cannot be empty in IoC_Match Object");
        }
        if (StringUtils.isBlank(iocValue)) {
            throw new IllegalArgumentException("ioc_value cannot be empty in IoC_Match Object");
        }
        if (StringUtils.isBlank(iocValue)) {
            throw new IllegalArgumentException("ioc_value cannot be empty in IoC_Match Object");
        }
        if (StringUtils.isBlank(iocScanJobId)) {
            throw new IllegalArgumentException("ioc_scan_job_id cannot be empty in IoC_Match Object");
        }
        if (StringUtils.isBlank(iocScanName)) {
            throw new IllegalArgumentException("ioc_scan_job_name cannot be empty in IoC_Match Object");
        }
        if (StringUtils.isBlank(executionId)) {
            throw new IllegalArgumentException("execution_id cannot be empty in IoC_Match Object");
        }
        if (timestamp == null) {
            throw new IllegalArgumentException("timestamp cannot be null in IoC_Match Object");
        }
        if(relatedDocIds == null || relatedDocIds.isEmpty()) {
            throw new IllegalArgumentException("related_doc_ids cannot be null or empty in IoC_Match Object");
        }
    }
}