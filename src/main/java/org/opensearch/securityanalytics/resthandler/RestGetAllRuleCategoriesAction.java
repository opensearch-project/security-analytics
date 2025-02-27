/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import java.io.IOException;
import java.util.List;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.GetAllRuleCategoriesAction;
import org.opensearch.securityanalytics.action.GetAllRuleCategoriesRequest;
import org.opensearch.transport.client.node.NodeClient;

import static org.opensearch.rest.RestRequest.Method.GET;

public class RestGetAllRuleCategoriesAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "get_all_rule_categories_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, SecurityAnalyticsPlugin.RULE_BASE_URI + "/categories"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        return channel -> client.execute(
                GetAllRuleCategoriesAction.INSTANCE,
                new GetAllRuleCategoriesRequest(),
                new RestToXContentListener<>(channel)
        );
    }
}
