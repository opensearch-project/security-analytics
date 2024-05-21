/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.model;

import java.io.IOException;
import java.util.Map;

import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.*;

/**
 * POJO containing Threat Intel Feed Metadata
 * Contains all the data necessary to fetch and parse threat intel IoC feeds.
 */
public class TIFMetadata implements Writeable, ToXContent {

    private static final ParseField FEED_ID_FIELD = new ParseField("id");
    private static final ParseField URL_FIELD = new ParseField("url");
    private static final ParseField NAME_FIELD = new ParseField("name");
    private static final ParseField ORGANIZATION_FIELD = new ParseField("organization");
    private static final ParseField DESCRIPTION_FIELD = new ParseField("description");
    private static final ParseField FEED_FORMAT = new ParseField("feed_format");
    private static final ParseField IOC_TYPE_FIELD = new ParseField("ioc_type");
    private static final ParseField IOC_COL_FIELD = new ParseField("ioc_col");
    private static final ParseField HAS_HEADER_FIELD = new ParseField("has_header");


    /**
     * @param feedId ID of the threat intel feed data
     * @return ID of the threat intel feed data
     */
    private String feedId;

    /**
     * @param url URL of the threat intel feed data
     * @return URL of the threat intel feed data
     */
    private String url;

    /**
     * @param name Name of the threat intel feed
     * @return Name of the threat intel feed
     */
    private String name;

    /**
     * @param organization A threat intel feed organization name
     * @return A threat intel feed organization name
     */
    private String organization;

    /**
     * @param description A description of the database
     * @return A description of a database
     */
    private String description;

    /**
     * @param feedType The type of the data feed (csv, json...)
     * @return The type of the data feed (csv, json...)
     */
    private String feedType;

    /**
     * @param iocCol the column of the ioc data if feedType is csv
     * @return the column of the ioc data if feedType is csv
     */
    private Integer iocCol;

    /**
     * @param containedIocs ioc type in feed
     * @return ioc type in feed
     */
    private String iocType;

    /**
     * @param hasHeader boolean if feed has a header
     * @return boolean if feed has a header
     */
    private Boolean hasHeader;

    public TIFMetadata(Map<String, Object> input) {
        this(
                input.get(FEED_ID_FIELD.getPreferredName()).toString(),
                input.get(URL_FIELD.getPreferredName()).toString(),
                input.get(NAME_FIELD.getPreferredName()).toString(),
                input.get(ORGANIZATION_FIELD.getPreferredName()).toString(),
                input.get(DESCRIPTION_FIELD.getPreferredName()).toString(),
                input.get(FEED_FORMAT.getPreferredName()).toString(),
                input.get(IOC_TYPE_FIELD.getPreferredName()).toString(),
                Integer.parseInt(input.get(IOC_COL_FIELD.getPreferredName()).toString()),
                (Boolean)input.get(HAS_HEADER_FIELD.getPreferredName())
            );
    }

    public String getUrl() {
        return url;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getFeedId() {
        return feedId;
    }

    public String getFeedType() {
        return feedType;
    }

    public Integer getIocCol() {
        return iocCol;
    }

    public String getIocType() {
        return iocType;
    }

    public Boolean hasHeader() {
        return hasHeader;
    }


    public TIFMetadata(final String feedId, final String url, final String name, final String organization, final String description,
                       final String feedType, final String iocType, final Integer iocCol, final Boolean hasHeader) {
        this.feedId = feedId;
        this.url = url;
        this.name = name;
        this.organization = organization;
        this.description = description;
        this.feedType = feedType;
        this.iocType = iocType;
        this.iocCol = iocCol;
        this.hasHeader = hasHeader;
    }


    /**
     * tif job metadata parser
     */
    public static final ConstructingObjectParser<TIFMetadata, Void> PARSER = new ConstructingObjectParser<>(
            "tif_metadata",
            true,
            args -> {
                String feedId = (String) args[0];
                String url = (String) args[1];
                String name = (String) args[2];
                String organization = (String) args[3];
                String description = (String) args[4];
                String feedType = (String) args[5];
                String containedIocs = (String) args[6];
                Integer iocCol = Integer.parseInt((String) args[7]);
                Boolean hasHeader = (Boolean) args[8];
                return new TIFMetadata(feedId, url, name, organization, description, feedType, containedIocs, iocCol, hasHeader);
            }
    );

    static {
        PARSER.declareString(ConstructingObjectParser.constructorArg(), FEED_ID_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), URL_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), NAME_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), ORGANIZATION_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), DESCRIPTION_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), FEED_FORMAT);
        PARSER.declareStringArray(ConstructingObjectParser.constructorArg(), IOC_TYPE_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), IOC_COL_FIELD);
        PARSER.declareBoolean(ConstructingObjectParser.constructorArg(), HAS_HEADER_FIELD);
    }

    public TIFMetadata(final StreamInput in) throws IOException {
        feedId = in.readString();
        url = in.readString();
        name = in.readString();
        organization = in.readString();
        description = in.readString();
        feedType = in.readString();
        iocType = in.readString();
        iocCol = in.readInt();
        hasHeader = in.readBoolean();
    }

    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(feedId);
        out.writeString(url);
        out.writeString(name);
        out.writeString(organization);
        out.writeString(description);
        out.writeString(feedType);
        out.writeString(iocType);
        out.writeInt(iocCol);
        out.writeBoolean(hasHeader);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject();
        builder.field(FEED_ID_FIELD.getPreferredName(), feedId);
        builder.field(URL_FIELD.getPreferredName(), url);
        builder.field(NAME_FIELD.getPreferredName(), name);
        builder.field(ORGANIZATION_FIELD.getPreferredName(), organization);
        builder.field(DESCRIPTION_FIELD.getPreferredName(), description);
        builder.field(FEED_FORMAT.getPreferredName(), feedType);
        builder.field(IOC_TYPE_FIELD.getPreferredName(), iocType);
        builder.field(IOC_COL_FIELD.getPreferredName(), iocCol);
        builder.field(HAS_HEADER_FIELD.getPreferredName(), hasHeader);
        builder.endObject();
        return builder;
    }

}
