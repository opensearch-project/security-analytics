/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper.resthandler;

import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.mapper.action.mapping.UpdateIndexMappingsAction;
import org.opensearch.securityanalytics.mapper.action.mapping.UpdateIndexMappingsRequest;

import java.io.IOException;
import java.util.List;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.PUT;

public class RestUpdateIndexMappingsAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "update_index_mappings_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        final UpdateIndexMappingsRequest updateIndexMappingsRequest = new UpdateIndexMappingsRequest(
                // TODO replace this with body
                request.param("indexName"),
                request.param("ruleTopic")
        );
        return channel -> client.execute(
                UpdateIndexMappingsAction.INSTANCE,
                updateIndexMappingsRequest,
                new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(PUT, SecurityAnalyticsPlugin.MAPPER_BASE_URI));
    }
}
