/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.util;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.SpecialPermission;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.securityanalytics.threatIntel.common.Constants;
import org.opensearch.securityanalytics.threatIntel.model.TIFMetadata;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Locale;

//Parser helper class
public class ThreatIntelFeedParser {
    private static final Logger log = LogManager.getLogger(ThreatIntelFeedParser.class);

    /**
     * Create CSVParser of a threat intel feed
     *
     * @param tifMetadata Threat intel feed metadata
     * @return parser for threat intel feed
     */
    @SuppressForbidden(reason = "Need to connect to http endpoint to read threat intel feed database file")
    public static CSVParser getThreatIntelFeedReaderCSV(final TIFMetadata tifMetadata) {
        try {
            validateUrl(new URL(tifMetadata.getUrl()));
        } catch (IOException e) {
            throw new OpenSearchException("Invalid threat intel feed URL [{}]", tifMetadata.getUrl(), e);
        }
        SpecialPermission.check();
        return AccessController.doPrivileged((PrivilegedAction<CSVParser>) () -> {
            try {
                URL url = new URL(tifMetadata.getUrl());
                URLConnection connection = url.openConnection();
                connection.addRequestProperty(Constants.USER_AGENT_KEY, Constants.USER_AGENT_VALUE);
                return new CSVParser(new BufferedReader(new InputStreamReader(connection.getInputStream())), CSVFormat.RFC4180);
            } catch (IOException e) {
                log.error("Exception: failed to read threat intel feed data from {}", tifMetadata.getUrl(), e);
                throw new OpenSearchException("failed to read threat intel feed data from {}", tifMetadata.getUrl(), e);
            }
        });
    }

    /**
     * Create CSVParser of a threat intel feed
     */
    @SuppressForbidden(reason = "Need to connect to http endpoint to read threat intel feed database file")
    public static CSVParser getThreatIntelFeedReaderCSV(URL url) {
        validateUrl(url);
        SpecialPermission.check();
        return AccessController.doPrivileged((PrivilegedAction<CSVParser>) () -> {
            try {
                URLConnection connection = url.openConnection();
                connection.addRequestProperty(Constants.USER_AGENT_KEY, Constants.USER_AGENT_VALUE);
                return new CSVParser(new BufferedReader(new InputStreamReader(connection.getInputStream())), CSVFormat.RFC4180);
            } catch (IOException e) {
                log.error("Exception: failed to read threat intel feed data from {}", url, e);
                throw new OpenSearchException("failed to read threat intel feed data from {}", url, e);
            }
        });
    }

    private static void validateUrl(URL url) {
        String protocol = url.getProtocol().toLowerCase(Locale.ROOT);
        if (!"http".equals(protocol) && !"https".equals(protocol)) {
            log.error("Unsupported protocol [{}]. Only http and https are allowed.", protocol);
            throw new OpenSearchException("Unsupported protocol [{}]. Only http and https are allowed.", protocol);
        }

        InetAddress address;
        try {
            address = InetAddress.getByName(url.getHost());
        } catch (UnknownHostException e) {
            log.error("Unable to resolve host [{}]", url.getHost());
            throw new OpenSearchException("Unable to resolve host [{}]", url.getHost());
        }

        if (address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isAnyLocalAddress()) {
            log.error("URL [{}] points to a restricted address. Loopback, link-local, and private addresses are not allowed.",
                    url);
            throw new OpenSearchException(
                    "URL [{}] points to a restricted address. Loopback, link-local, and private addresses are not allowed.",
                    url
            );
        }
    }
}
