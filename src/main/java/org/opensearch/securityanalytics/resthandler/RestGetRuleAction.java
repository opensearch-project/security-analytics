/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestActions;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.rest.RestRequest.Method.GET;

import org.opensearch.securityanalytics.action.GetRuleAction;
import org.opensearch.securityanalytics.action.GetRuleRequest;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;

public class RestGetRuleAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "get_rule_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, String.format(Locale.getDefault(), "%s/{%s}", SecurityAnalyticsPlugin.RULE_BASE_URI, GetRuleRequest.RULE_ID)));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String ruleId = request.param(GetRuleRequest.RULE_ID, Rule.NO_ID);
        Boolean isPrepackaged = request.paramAsBoolean(GetRuleRequest.IS_PREPACKAGED, false);

        if (ruleId == null || ruleId.isEmpty()) {
            throw new IllegalArgumentException("missing id");
        }

        GetRuleRequest req = new GetRuleRequest(ruleId, isPrepackaged, RestActions.parseVersion(request));
        return channel -> client.execute(
                GetRuleAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }
}
