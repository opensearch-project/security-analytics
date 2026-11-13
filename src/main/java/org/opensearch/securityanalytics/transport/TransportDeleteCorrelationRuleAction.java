/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.transport;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.inject.Inject;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequestBuilder;
import org.opensearch.index.reindex.ScrollableHitSource;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.DeleteCorrelationRuleAction;
import org.opensearch.securityanalytics.action.DeleteCorrelationRuleRequest;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.resources.SecurityAnalyticsPluginClient;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportDeleteCorrelationRuleAction extends HandledTransportAction<DeleteCorrelationRuleRequest, AcknowledgedResponse> {

    private static final Logger log = LogManager.getLogger(TransportDeleteCorrelationRuleAction.class);

    private final SecurityAnalyticsPluginClient pluginClient;

    private CorrelationAlertService correlationAlertService;


    @Inject
    public TransportDeleteCorrelationRuleAction(
        TransportService transportService,
        SecurityAnalyticsPluginClient pluginClient,
        ActionFilters actionFilters,
        CorrelationAlertService correlationAlertService
    ) {
        super(DeleteCorrelationRuleAction.NAME, transportService, actionFilters, DeleteCorrelationRuleRequest::new);
        this.pluginClient = pluginClient;
        this.correlationAlertService = correlationAlertService;
    }

    @Override
    protected void doExecute(Task task, DeleteCorrelationRuleRequest request, ActionListener<AcknowledgedResponse> listener) {
        String correlationRuleId = request.getCorrelationRuleId();
        WriteRequest.RefreshPolicy refreshPolicy = request.getRefreshPolicy();
        log.debug("Deleting Correlation Rule with id: " + correlationRuleId);

        new DeleteByQueryRequestBuilder(pluginClient, DeleteByQueryAction.INSTANCE)
            .source(CorrelationRule.CORRELATION_RULE_INDEX)
            .filter(QueryBuilders.matchQuery("_id", correlationRuleId))
            .refresh(true)
            .execute(new ActionListener<>() {
                @Override
                public void onResponse(BulkByScrollResponse response) {
                    if (response.isTimedOut()) {
                        listener.onFailure(
                                new OpenSearchStatusException(
                                    String.format(
                                            Locale.getDefault(),
                                            "Request timed out. Correlation Rule with id %s cannot be deleted",
                                            correlationRuleId
                                    ),
                                    RestStatus.REQUEST_TIMEOUT)
                        );
                        return;
                    }
                    // A delete by query lists a failed document or a failed shard in the response instead of
                    // failing the request, so the rule can still be there. The alerts keep their state until the
                    // caller retries the delete.
                    if (!response.getBulkFailures().isEmpty() || !response.getSearchFailures().isEmpty()) {
                        OpenSearchStatusException failure = buildDeleteFailure(correlationRuleId, response);
                        // This path does not go through SecurityAnalyticsException.wrap, which is where the other
                        // branch logs
                        log.error("Correlation Rule with id {} was not deleted, {} of {} documents deleted",
                                correlationRuleId, response.getDeleted(), response.getStatus().getTotal(), failure);
                        listener.onFailure(failure);
                        return;
                    }
                    // update the alerts assosciated with correlation Rules, with error STATE and errorMessage
                    log.debug("Updating Correlation Alerts with error Message for ruleId: " + correlationRuleId);
                    correlationAlertService.updateCorrelationAlertsWithError(correlationRuleId);
                    listener.onResponse(new AcknowledgedResponse(true));
                }

                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(SecurityAnalyticsException.wrap(e));
                }
            });
    }

    /**
     * Builds the failure for a delete by query that listed failures in its response. The status is the highest one
     * the response lists, as the core REST layer does for a by query response, so a denial is not hidden behind a
     * version conflict from another shard. The first listed failure becomes the cause, so the caller and the log
     * keep a stack trace.
     *
     * @param correlationRuleId the rule the request was for
     * @param response a response that lists at least one bulk or search failure
     * @return a status exception naming the rule and every reason the response listed
     */
    private static OpenSearchStatusException buildDeleteFailure(String correlationRuleId, BulkByScrollResponse response) {
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
            String.format(
                Locale.getDefault(),
                "Correlation Rule with id %s cannot be deleted: %s",
                correlationRuleId,
                String.join("; ", reasons)
            ),
            status,
            cause
        );
    }

    /** Returns whichever of the two statuses has the higher code. */
    private static RestStatus higherOf(RestStatus status, RestStatus other) {
        return other.getStatus() > status.getStatus() ? other : status;
    }
}
