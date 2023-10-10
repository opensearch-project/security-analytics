/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.common;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.CharBuffer;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.SpecialPermission;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.ParseField;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ConstructingObjectParser;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

/**
 * Threat intel tif job metadata object
 *
 * Manifest file is stored in an external endpoint. OpenSearch read the file and store values it in this object.
 */
public class TIFMetadata {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private static final ParseField FEED_ID = new ParseField("id");
    private static final ParseField URL_FIELD = new ParseField("url");
    private static final ParseField NAME = new ParseField("name");
    private static final ParseField ORGANIZATION = new ParseField("organization");
    private static final ParseField DESCRIPTION = new ParseField("description");
    private static final ParseField FEED_TYPE = new ParseField("feed_type");
    private static final ParseField CONTAINED_IOCS = new ParseField("contained_iocs");
    private static final ParseField IOC_COL = new ParseField("ioc_col");

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
    private String iocCol;

    /**
     * @param containedIocs list of ioc types contained in feed
     * @return list of ioc types contained in feed
     */
    private List<String> containedIocs;


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
    public String getIocCol() {
        return iocCol;
    }
    public List<String> getContainedIocs() {
        return containedIocs;
    }

    public TIFMetadata(final String feedId, final String url, final String name, final String organization, final String description, final String feedType, final List<String> containedIocs, final String iocCol) {
        this.feedId = feedId;
        this.url = url;
        this.name = name;
        this.organization = organization;
        this.description = description;
        this.feedType = feedType;
        this.containedIocs = containedIocs;
        this.iocCol = iocCol;
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
                List<String> containedIocs = (List<String>) args[6];
                String iocCol = (String) args[7];
                return new TIFMetadata(feedId, url, name, organization, description, feedType, containedIocs, iocCol);
            }
    );
    static {
        PARSER.declareString(ConstructingObjectParser.constructorArg(), FEED_ID);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), URL_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), NAME);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), ORGANIZATION);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), DESCRIPTION);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), FEED_TYPE);
        PARSER.declareStringArray(ConstructingObjectParser.constructorArg(), CONTAINED_IOCS);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), IOC_COL);
    }

    /**
     * TIFMetadata builder
     */
    public static class Builder { //TODO: builder?
        private static final int FILE_MAX_BYTES = 1024 * 8;

        /**
         * Build TIFMetadata from a given url
         *
         * @param url url to downloads a manifest file
         * @return TIFMetadata representing the manifest file
         */
        @SuppressForbidden(reason = "Need to connect to http endpoint to read manifest file") // change permissions
        public static TIFMetadata build(final URL url) {
            SpecialPermission.check();
            return AccessController.doPrivileged((PrivilegedAction<TIFMetadata>) () -> {
                try {
                    URLConnection connection = url.openConnection();
                    return internalBuild(connection);
                } catch (IOException e) {
                    log.error("Runtime exception connecting to the manifest file", e);
                    throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
                }
            });
        }

        @SuppressForbidden(reason = "Need to connect to http endpoint to read manifest file")
        protected static TIFMetadata internalBuild(final URLConnection connection) throws IOException {
            connection.addRequestProperty(Constants.USER_AGENT_KEY, Constants.USER_AGENT_VALUE);
            InputStreamReader inputStreamReader = new InputStreamReader(connection.getInputStream());
            try (BufferedReader reader = new BufferedReader(inputStreamReader)) {
                CharBuffer charBuffer = CharBuffer.allocate(FILE_MAX_BYTES);
                reader.read(charBuffer);
                charBuffer.flip();
                XContentParser parser = JsonXContent.jsonXContent.createParser(
                        NamedXContentRegistry.EMPTY,
                        DeprecationHandler.IGNORE_DEPRECATIONS,
                        charBuffer.toString()
                );
                return PARSER.parse(parser, null);
            }
        }
    }
}
