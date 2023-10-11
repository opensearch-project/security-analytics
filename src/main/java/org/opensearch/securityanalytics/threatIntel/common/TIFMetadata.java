/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.common;

import java.io.IOException;
import java.util.List;

import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.*;

/**
 * Threat Intel Feed Config Metadata Object
 *
 */
public class TIFMetadata implements ToXContent{
    private static final ParseField FEED_ID = new ParseField("id");
    private static final ParseField URL_FIELD = new ParseField("url");
    private static final ParseField NAME = new ParseField("name");
    private static final ParseField ORGANIZATION = new ParseField("organization");
    private static final ParseField DESCRIPTION = new ParseField("description");
    private static final ParseField FEED_TYPE = new ParseField("feed_type");
    private static final ParseField CONTAINED_IOCS = new ParseField("contained_iocs");
    private static final ParseField IOC_COL = new ParseField("ioc_col");
    private static final ParseField HAS_HEADER = new ParseField("has_header");

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
     * @param containedIocs list of ioc types contained in feed
     * @return list of ioc types contained in feed
     */
    private List<String> containedIocs;

    private Boolean hasHeader;

    public  TIFMetadata(final String feedId, final String url, final String name, final String organization, final String description,
                       final String feedType, final List<String> containedIocs, final Integer iocCol, final Boolean hasHeader) {
        this.feedId = feedId;
        this.url = url;
        this.name = name;
        this.organization = organization;
        this.description = description;
        this.feedType = feedType;
        this.containedIocs = containedIocs;
        this.iocCol = iocCol;
        this.hasHeader = hasHeader;
    }

    public String getUrl() {
        return url;
    }
    public String getName() {
        return name;
    }
    public String getOrganization() {
        return organization;
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
    public List<String> getContainedIocs() {
        return containedIocs;
    }
    public Boolean hasHeader() {
        return hasHeader;
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject();
        builder.field(FEED_ID.getPreferredName(), feedId);
        builder.field(URL_FIELD.getPreferredName(), url);
        builder.field(NAME.getPreferredName(), name);
        builder.field(ORGANIZATION.getPreferredName(), organization);
        builder.field(DESCRIPTION.getPreferredName(), description);
        builder.field(FEED_TYPE.getPreferredName(), feedType);
        builder.field(CONTAINED_IOCS.getPreferredName(), containedIocs);
        builder.field(IOC_COL.getPreferredName(), iocCol);
        builder.field(HAS_HEADER.getPreferredName(), hasHeader);
        builder.endObject();
        return builder;
    }
}
