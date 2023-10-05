/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import java.io.IOException;
import java.util.List;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * Rest handler for threat intel datasource update request
 */
public class RestUpdateDatasourceHandler extends BaseRestHandler {
    private static final String ACTION_NAME = "threatintel_datasource_update";

    @Override
    public String getName() {
        return ACTION_NAME;
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        final UpdateDatasourceRequest updateDatasourceRequest = new UpdateDatasourceRequest(request.param("name"));
        if (request.hasContentOrSourceParam()) {
            try (XContentParser parser = request.contentOrSourceParamParser()) {
                UpdateDatasourceRequest.PARSER.parse(parser, updateDatasourceRequest, null);
            }
        }
        return channel -> client.executeLocally(
            UpdateDatasourceAction.INSTANCE,
            updateDatasourceRequest,
            new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        String path = String.join("/", "/_plugins/_security_analytics", "threatintel/datasource/{name}/_settings");
        return List.of(new Route(PUT, path));
    }
}
