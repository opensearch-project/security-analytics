/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.DeleteCorrelationRuleAction;
import org.opensearch.securityanalytics.action.DeleteCorrelationRuleRequest;
import org.opensearch.securityanalytics.action.DeleteRuleAction;

import static org.opensearch.securityanalytics.util.RestHandlerUtils.REFRESH;

public class RestDeleteCorrelationRuleAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestDeleteCorrelationRuleAction.class);

    @Override
    public String getName() {
        return "delete_correlation_rule_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.DELETE, String.format(Locale.getDefault(), "%s/{correlation_rule_id}", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI))
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s/{correlation_rule_id}", request.method(), SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI));

        String ruleID = request.param("correlation_rule_id");

        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.parse(request.param(REFRESH, WriteRequest.RefreshPolicy.IMMEDIATE.getValue()));
        DeleteCorrelationRuleRequest deleteRequest = new DeleteCorrelationRuleRequest(ruleID, refreshPolicy);
        return channel -> client.execute(DeleteCorrelationRuleAction.INSTANCE, deleteRequest, new RestToXContentListener<>(channel));
    }
}