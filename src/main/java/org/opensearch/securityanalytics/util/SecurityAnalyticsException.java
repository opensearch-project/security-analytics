/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.common.Strings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestStatus;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

public class SecurityAnalyticsException extends OpenSearchException {

    private static final Logger log = LogManager.getLogger(SecurityAnalyticsException.class);

    private final String message;

    private final RestStatus status;

    private final Exception ex;

    public SecurityAnalyticsException(String message, RestStatus status, Exception ex) {
        super(message, ex);
        this.message = message;
        this.status = status;
        this.ex = ex;
    }

    @Override
    public RestStatus status() {
        return status;
    }

    public static OpenSearchException wrap(Exception ex) {
        log.error("Security Analytics error:", ex);

        String friendlyMsg = "Unknown error";
        RestStatus status = RestStatus.INTERNAL_SERVER_ERROR;

        if (!Strings.isNullOrEmpty(ex.getMessage())) {
            friendlyMsg = ex.getMessage();
        }

        return new SecurityAnalyticsException(friendlyMsg, status, new Exception(String.format(Locale.getDefault(), "%s: %s", ex.getClass().getName(), ex.getMessage())));
    }

    public static OpenSearchException wrap(OpenSearchException ex) {
        log.error("Security Analytics error:", ex);

        String friendlyMsg = "Unknown error";
        RestStatus status = ex.status();

        if (!Strings.isNullOrEmpty(ex.getMessage())) {
            friendlyMsg = ex.getMessage();
        }

        return new SecurityAnalyticsException(friendlyMsg, status, new Exception(String.format(Locale.getDefault(), "%s: %s", ex.getClass().getName(), ex.getMessage())));
    }

    public static OpenSearchException wrap(List<Exception> ex) {
        try {
            RestStatus status = RestStatus.BAD_REQUEST;

            XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
            for (Exception e: ex) {
                builder.field("error", e.getMessage());
                log.error("Security Analytics error:", e);
            }
            builder.endObject();
            String friendlyMsg = Strings.toString(builder);

            return new SecurityAnalyticsException(friendlyMsg, status, new Exception(String.format(Locale.getDefault(), "%s: %s", ex.getClass().getName(), friendlyMsg)));
        } catch (IOException e) {
            return SecurityAnalyticsException.wrap(e);
        }
    }
}