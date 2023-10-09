package org.opensearch.securityanalytics.threatIntel;

import com.fasterxml.jackson.core.JsonParser;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.SpecialPermission;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.compress.Compressor;
import org.opensearch.core.compress.CompressorRegistry;
import org.opensearch.core.xcontent.*;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;
import org.opensearch.securityanalytics.threatIntel.common.Constants;
import org.opensearch.securityanalytics.threatIntel.common.DatasourceManifest;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.time.Instant;

//Parser helper class
public class ThreatIntelFeedParser {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    /**
     * Create CSVParser of a threat intel feed
     *
     * @param manifest Datasource manifest
     * @return parser for threat intel feed
     */
    @SuppressForbidden(reason = "Need to connect to http endpoint to read threat intel feed database file")
    public static CSVParser getThreatIntelFeedReaderCSV(final DatasourceManifest manifest) {
        SpecialPermission.check();
        return AccessController.doPrivileged((PrivilegedAction<CSVParser>) () -> {
            try {
                URL url = new URL(manifest.getUrl());
                URLConnection connection = url.openConnection();
                connection.addRequestProperty(Constants.USER_AGENT_KEY, Constants.USER_AGENT_VALUE);
                return new CSVParser(new BufferedReader(new InputStreamReader(connection.getInputStream())), CSVFormat.RFC4180);
            } catch (IOException e) {
                log.error("Exception: failed to read threat intel feed data from {}",manifest.getUrl(), e);
                throw new OpenSearchException("failed to read threat intel feed data from {}", manifest.getUrl(), e);
            }
        });
    }

    /**
     * Validate header
     *
     * 1. header should not be null
     * 2. the number of values in header should be more than one
     *
     * @param header the header
     * @return CSVRecord the input header
     */
    public static CSVRecord validateHeader(CSVRecord header) {
        if (header == null) {
            throw new OpenSearchException("threat intel feed database is empty");
        }
        if (header.values().length < 2) {
            throw new OpenSearchException("threat intel feed database should have at least two fields");
        }
        return header;
    }
}
