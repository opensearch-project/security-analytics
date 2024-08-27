/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.transport;

import java.util.Collections;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequestBuilder;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.DeleteCorrelationRuleAction;
import org.opensearch.securityanalytics.action.DeleteCorrelationRuleRequest;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportDeleteCorrelationRuleAction extends HandledTransportAction<DeleteCorrelationRuleRequest, AcknowledgedResponse> {

    private static final Logger log = LogManager.getLogger(TransportDeleteCorrelationRuleAction.class);

    private final Client client;

    private CorrelationAlertService correlationAlertService;


    @Inject
    public TransportDeleteCorrelationRuleAction(
        TransportService transportService,
        Client client,
        ActionFilters actionFilters,
        CorrelationAlertService correlationAlertService
    ) {
        super(DeleteCorrelationRuleAction.NAME, transportService, actionFilters, DeleteCorrelationRuleRequest::new);
        this.client = client;
        this.correlationAlertService = correlationAlertService;
    }

    @Override
    protected void doExecute(Task task, DeleteCorrelationRuleRequest request, ActionListener<AcknowledgedResponse> listener) {
        String correlationRuleId = request.getCorrelationRuleId();
        WriteRequest.RefreshPolicy refreshPolicy = request.getRefreshPolicy();
        log.debug("Deleting Correlation Rule with id: " + correlationRuleId);

        new DeleteByQueryRequestBuilder(client, DeleteByQueryAction.INSTANCE)
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
}
