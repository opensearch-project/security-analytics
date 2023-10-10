package org.opensearch.securityanalytics.threatIntel.common;

import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ConstructingObjectParser;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.List;

/**
 * Database of a tif job
 */
public class FeedMetadata implements Writeable, ToXContent { //feedmetadata
    private static final ParseField FEED_ID = new ParseField("feed_id");
    private static final ParseField FEED_NAME = new ParseField("feed_name");
    private static final ParseField FEED_FORMAT = new ParseField("feed_format");
    private static final ParseField ENDPOINT_FIELD = new ParseField("endpoint");
    private static final ParseField DESCRIPTION = new ParseField("description");
    private static final ParseField ORGANIZATION = new ParseField("organization");
    private static final ParseField CONTAINED_IOCS_FIELD = new ParseField("contained_iocs_field");
    private static final ParseField IOC_COL = new ParseField("ioc_col");
    private static final ParseField FIELDS_FIELD = new ParseField("fields");

    /**
     * @param feedId id of the feed
     * @return id of the feed
     */
    private String feedId;

    /**
     * @param feedFormat format of the feed (csv, json...)
     * @return the type of feed ingested
     */
    private String feedFormat;

    /**
     * @param endpoint URL of a manifest file
     * @return URL of a manifest file
     */
    private String endpoint;

    /**
     * @param feedName name of the threat intel feed
     * @return name of the threat intel feed
     */
    private String feedName;

    /**
     * @param description description of the threat intel feed
     * @return description of the threat intel feed
     */
    private String description;

    /**
     * @param organization organization of the threat intel feed
     * @return organization of the threat intel feed
     */
    private String organization;

    /**
     * @param contained_iocs_field list of iocs contained in a given feed
     * @return list of iocs contained in a given feed
     */
    private List<String> contained_iocs_field;

    /**
     * @param ioc_col column of the contained ioc
     * @return column of the contained ioc
     */
    private String iocCol;

    /**
     * @param fields A list of available fields in the database
     * @return A list of available fields in the database
     */
    private List<String> fields;

    public FeedMetadata(String feedId, String feedName, String feedFormat, final String endpoint, final String description,
                        final String organization, final List<String> contained_iocs_field, final String iocCol, final List<String> fields) {
        this.feedId = feedId;
        this.feedName = feedName;
        this.feedFormat = feedFormat;
        this.endpoint = endpoint;
        this.description = description;
        this.organization = organization;
        this.contained_iocs_field = contained_iocs_field;
        this.iocCol = iocCol;
        this.fields = fields;
    }

    private static final ConstructingObjectParser<FeedMetadata, Void> PARSER = new ConstructingObjectParser<>(
            "tif_metadata_database",
            true,
            args -> {
                String feedId = (String) args[0];
                String feedName = (String) args[1];
                String feedFormat = (String) args[2];
                String endpoint = (String) args[3];
                String description = (String) args[4];
                String organization = (String) args[5];
                List<String> contained_iocs_field = (List<String>) args[6];
                String iocCol = (String) args[7];
                List<String> fields = (List<String>) args[8];
                return new FeedMetadata(feedFormat, endpoint, feedId, feedName, description, organization, contained_iocs_field, iocCol, fields);
            }
    );
    static {
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), FEED_ID);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), FEED_NAME);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), FEED_FORMAT);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), ENDPOINT_FIELD);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), DESCRIPTION);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), ORGANIZATION);
        PARSER.declareStringArray(ConstructingObjectParser.constructorArg(), CONTAINED_IOCS_FIELD);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), IOC_COL);
        PARSER.declareStringArray(ConstructingObjectParser.optionalConstructorArg(), FIELDS_FIELD);
    }

    public FeedMetadata(final StreamInput in) throws IOException {
        feedId = in.readString();
        feedName = in.readString();
        feedFormat = in.readString();
        endpoint = in.readString();
        description = in.readString();
        organization = in.readString();
        contained_iocs_field = in.readStringList();
        iocCol = in.readString();
        fields = in.readOptionalStringList();
    }

    private FeedMetadata(){}

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(feedId);
        out.writeString(feedName);
        out.writeString(feedFormat);
        out.writeString(endpoint);
        out.writeString(description);
        out.writeString(organization);
        out.writeStringCollection(contained_iocs_field);
        out.writeString(iocCol);
        out.writeOptionalStringCollection(fields);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject();
        builder.field(FEED_ID.getPreferredName(), feedId);
        builder.field(FEED_NAME.getPreferredName(), feedName);
        builder.field(FEED_FORMAT.getPreferredName(), feedFormat);
        builder.field(ENDPOINT_FIELD.getPreferredName(), endpoint);
        builder.field(DESCRIPTION.getPreferredName(), description);
        builder.field(ORGANIZATION.getPreferredName(), organization);
        builder.field(CONTAINED_IOCS_FIELD.getPreferredName(), contained_iocs_field);
        builder.field(IOC_COL.getPreferredName(), iocCol);

//            if (provider != null) {
//                builder.field(PROVIDER_FIELD.getPreferredName(), provider);
//            }
//            if (updatedAt != null) {
//                builder.timeField(
//                        UPDATED_AT_FIELD.getPreferredName(),
//                        UPDATED_AT_FIELD_READABLE.getPreferredName(),
//                        updatedAt.toEpochMilli()
//                );
//            }
        if (fields != null) {
            builder.startArray(FIELDS_FIELD.getPreferredName());
            for (String field : fields) {
                builder.value(field);
            }
            builder.endArray();
        }
        builder.endObject();
        return builder;
    }

    public String getFeedId() {
        return feedId;
    }

    public String getFeedFormat() {
        return feedFormat;
    }

    public String getFeedName() {
        return feedName;
    }

    public String getDescription() {
        return description;
    }

    public String getOrganization() {
        return organization;
    }

    public List<String> getContained_iocs_field() {
        return contained_iocs_field;
    }

    public String getIocCol() {
        return iocCol;
    }

    public String getEndpoint() {
        return this.endpoint;
    }

    public List<String> getFields() {
        return fields;
    }
    public void setFeedId(String feedId) {
        this.feedId = feedId;
    }

    public void setFeedFormat(String feedFormat) {
        this.feedFormat = feedFormat;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public void setFeedName(String feedName) {
        this.feedName = feedName;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public void setContained_iocs_field(List<String> contained_iocs_field) {
        this.contained_iocs_field = contained_iocs_field;
    }

    public void setIocCol(String iocCol) {
        this.iocCol = iocCol;
    }

    public void setFields(List<String> fields) {
        this.fields = fields;
    }

    /**
     * Reset database so that it can be updated in next run regardless there is new update or not
     */
    public void resetTIFMetadata() {
        this.setFeedId(null);
        this.setFeedName(null);
        this.setFeedFormat(null);
        this.setEndpoint(null);
        this.setDescription(null);
        this.setOrganization(null);
        this.setContained_iocs_field(null);
        this.setIocCol(null);
        this.setFeedFormat(null);
    }

    /**
     * Set database attributes with given input
     *
     * @param tifMetadata the tif metadata
     * @param fields the fields
     */
    public void setTIFMetadata(final TIFMetadata tifMetadata, final List<String> fields) {
        this.feedId = tifMetadata.getFeedId();
        this.feedName = tifMetadata.getName();
        this.feedFormat = tifMetadata.getFeedType();
        this.endpoint = tifMetadata.getUrl();
        this.organization = tifMetadata.getOrganization();
        this.description = tifMetadata.getDescription();
        this.contained_iocs_field = tifMetadata.getContainedIocs();
        this.iocCol = tifMetadata.getIocCol();
        this.fields = fields;
    }

}
