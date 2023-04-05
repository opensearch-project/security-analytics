/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import java.io.IOException;
import java.util.List;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.GetIndexMappingsAction;
import org.opensearch.securityanalytics.action.GetIndexMappingsRequest;
import org.opensearch.securityanalytics.action.GetMappingsViewAction;
import org.opensearch.securityanalytics.action.GetMappingsViewRequest;


import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RestGetMappingsViewAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "index_mappings_get_view_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        GetMappingsViewRequest req;
        if (!request.hasContentOrSourceParam()) {
            req = new GetMappingsViewRequest(
                    request.param(GetMappingsViewRequest.INDEX_NAME_FIELD),
                    request.param(GetMappingsViewRequest.RULE_TOPIC_FIELD)
            );
        } else {
            try (XContentParser parser = request.contentOrSourceParamParser()) {
                req = GetMappingsViewRequest.parse(parser);
            }
        }

        return channel -> client.execute(
                GetMappingsViewAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI));
    }
}
