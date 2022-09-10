/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.CreateIndexMappingsAction;
import org.opensearch.securityanalytics.action.CreateIndexMappingsRequest;

import java.io.IOException;
import java.util.List;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.POST;

public class RestCreateIndexMappingsAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "index_mappings_create_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        CreateIndexMappingsRequest req;
        if (!request.hasContentOrSourceParam()) {
            req = new CreateIndexMappingsRequest(
                    request.param("indexName"),
                    request.param("ruleTopic")
            );
        } else {
            try (XContentParser parser = request.contentOrSourceParamParser()) {
                req = CreateIndexMappingsRequest.parse(parser);
            }
        }

        return channel -> client.execute(
                CreateIndexMappingsAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(POST, SecurityAnalyticsPlugin.MAPPER_BASE_URI));
    }
}
