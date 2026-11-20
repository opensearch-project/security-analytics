/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.transport;

import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.DeleteCorrelationRuleAction;
import org.opensearch.securityanalytics.action.DeleteCorrelationRuleRequest;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.resources.SecurityAnalyticsPluginClient;
import org.opensearch.securityanalytics.util.ByQueryResponses;
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
                    OpenSearchStatusException failure = ByQueryResponses.listedFailure(
                            String.format(Locale.getDefault(), "Correlation Rule with id %s cannot be deleted", correlationRuleId),
                            response
                    );
                    if (failure != null) {
                        // This path does not go through SecurityAnalyticsException.wrap, which is where the other
                        // branch logs
                        log.error("Delete of Correlation Rule with id {} reported failures, {} of {} documents deleted",
                                correlationRuleId, response.getDeleted(), response.getStatus().getTotal(), failure);
                        listener.onFailure(failure);
                        return;
                    }
                    // Marks the rule's alerts as errored, and answers once that is done or has failed.
                    log.debug("Updating Correlation Alerts with error Message for ruleId: " + correlationRuleId);
                    correlationAlertService.updateCorrelationAlertsWithError(correlationRuleId, ActionListener.wrap(
                            r -> listener.onResponse(new AcknowledgedResponse(true)),
                            e -> {
                                log.error("Correlation Rule with id {} was deleted, but its alerts were not marked as errored", correlationRuleId, e);
                                listener.onFailure(SecurityAnalyticsException.wrap(e));
                            }
                    ));
                }

                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(SecurityAnalyticsException.wrap(e));
                }
            });
    }

}
