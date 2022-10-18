/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.DeleteRuleAction;
import org.opensearch.securityanalytics.action.DeleteRuleRequest;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.securityanalytics.util.RestHandlerUtils.REFRESH;

public class RestDeleteRuleAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestDeleteRuleAction.class);

    @Override
    public String getName() {
        return "delete_rule_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.DELETE, String.format(Locale.getDefault(), "%s/{ruleID}", SecurityAnalyticsPlugin.RULE_BASE_URI))
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s/{ruleID}", request.method(), SecurityAnalyticsPlugin.RULE_BASE_URI));

        String ruleID = request.param("ruleID");
        Boolean forced = request.paramAsBoolean("forced", false);

        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.parse(request.param(REFRESH, WriteRequest.RefreshPolicy.IMMEDIATE.getValue()));
        DeleteRuleRequest deleteRuleRequest = new DeleteRuleRequest(ruleID, refreshPolicy, forced);
        return channel -> client.execute(DeleteRuleAction.INSTANCE, deleteRuleRequest, new RestToXContentListener<>(channel));
    }
}