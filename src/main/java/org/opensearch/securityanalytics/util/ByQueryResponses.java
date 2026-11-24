/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.ScrollableHitSource;

/** Turns the failures a delete or update by query lists in its response into an exception. */
public final class ByQueryResponses {

    private ByQueryResponses() {}

    /**
     * Returns the failure a by query response lists, or null when it lists none. A by query request lists a failed
     * document or a failed shard in its response instead of failing. The status is the highest one listed, as the core
     * REST layer reports it, and the first listed failure becomes the cause.
     *
     * @param message what could not be done, the start of the exception message
     * @param response the by query response
     * @return a status exception naming every listed reason, or null
     */
    public static OpenSearchStatusException listedFailure(String message, BulkByScrollResponse response) {
        if (response.getBulkFailures().isEmpty() && response.getSearchFailures().isEmpty()) {
            return null;
        }
        List<String> reasons = new ArrayList<>();
        RestStatus status = RestStatus.OK;
        Throwable cause = null;
        for (BulkItemResponse.Failure failure : response.getBulkFailures()) {
            reasons.add(failure.getMessage());
            status = higherOf(status, failure.getStatus());
            if (cause == null) {
                cause = failure.getCause();
            }
        }
        for (ScrollableHitSource.SearchFailure failure : response.getSearchFailures()) {
            reasons.add(failure.getReason().toString());
            status = higherOf(status, failure.getStatus());
            if (cause == null) {
                cause = failure.getReason();
            }
        }
        return new OpenSearchStatusException(
                String.format(Locale.getDefault(), "%s: %s", message, String.join("; ", reasons)),
                status,
                cause
        );
    }

    private static RestStatus higherOf(RestStatus status, RestStatus other) {
        return other.getStatus() > status.getStatus() ? other : status;
    }
}
