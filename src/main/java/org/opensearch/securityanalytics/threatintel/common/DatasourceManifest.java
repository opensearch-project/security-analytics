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
 * Threat intel datasource manifest file object
 *
 * Manifest file is stored in an external endpoint. OpenSearch read the file and store values it in this object.
 */
public class DatasourceManifest {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private static final ParseField URL_FIELD = new ParseField("url"); //url for csv threat intel feed
    private static final ParseField DB_NAME_FIELD = new ParseField("db_name"); // name of the db (csv file for now)
    private static final ParseField PROVIDER_FIELD = new ParseField("provider"); // provider of the db
    private static final ParseField UPDATED_AT_FIELD = new ParseField("updated_at_in_epoch_milli"); // last updated time

    private static final ParseField SHA256_HASH_FIELD = new ParseField("sha256_hash"); //not using for now
    private static final ParseField DESCRIPTION_FIELD = new ParseField("description"); //not using for now

    /**
     * @param url URL of a ZIP file containing a database
     * @return URL of a ZIP file containing a database
     */
    private String url;

    /**
     * @param dbName A database file name inside the ZIP file
     * @return A database file name inside the ZIP file
     */
    private String dbName;
    /**
     * @param sha256Hash SHA256 hash value of a database file
     * @return SHA256 hash value of a database file
     */
    private String sha256Hash;

    /**
     * @param organization A database organization name
     * @return A database organization name
     */
    private String provider;
    /**
     * @param description A description of the database
     * @return A description of a database
     */
    private String description;
    /**
     * @param updatedAt A date when the database was updated
     * @return A date when the database was updated
     */
    private Long updatedAt;

    public String getUrl() {
        return this.url;
    }
    public String getDbName() {
        return dbName;
    }

    public String getProvider() {
        return provider;
    }

    public String getSha256Hash() {
        return sha256Hash;
    }

    public String getDescription() {
        return description;
    }

    public Long getUpdatedAt() {
        return updatedAt;
    }

    public DatasourceManifest(final String url, final String dbName, final String provider, final Long updatedAt) {
        this.url = url;
        this.dbName = dbName;
        this.provider = provider;
        this.updatedAt = updatedAt;
    }

    /**
     * Datasource manifest parser
     */
    public static final ConstructingObjectParser<DatasourceManifest, Void> PARSER = new ConstructingObjectParser<>(
            "datasource_manifest",
            true,
            args -> {
                String url = (String) args[0];
                String dbName = (String) args[1];
                String provider = (String) args[2];
                Long updatedAt = (Long) args[3];
                return new DatasourceManifest(url, dbName, provider, updatedAt);
            }
    );
    static {
        PARSER.declareString(ConstructingObjectParser.constructorArg(), URL_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), DB_NAME_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), PROVIDER_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), UPDATED_AT_FIELD);

    }

    /**
     * Datasource manifest builder
     */
    public static class Builder {
        private static final int MANIFEST_FILE_MAX_BYTES = 1024 * 8;

        /**
         * Build DatasourceManifest from a given url
         *
         * @param url url to downloads a manifest file
         * @return DatasourceManifest representing the manifest file
         */
        @SuppressForbidden(reason = "Need to connect to http endpoint to read manifest file") // change permissions
        public static DatasourceManifest build(final URL url) {
            SpecialPermission.check();
            return AccessController.doPrivileged((PrivilegedAction<DatasourceManifest>) () -> {
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
        protected static DatasourceManifest internalBuild(final URLConnection connection) throws IOException {
            connection.addRequestProperty(Constants.USER_AGENT_KEY, Constants.USER_AGENT_VALUE);
            InputStreamReader inputStreamReader = new InputStreamReader(connection.getInputStream());
            try (BufferedReader reader = new BufferedReader(inputStreamReader)) {
                CharBuffer charBuffer = CharBuffer.allocate(MANIFEST_FILE_MAX_BYTES);
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
