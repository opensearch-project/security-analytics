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
 * Rest handler for threat intel tif job update request
 */
public class RestUpdateTIFJobHandler extends BaseRestHandler {
    private static final String ACTION_NAME = "threatintel_tifjob_update";

    @Override
    public String getName() {
        return ACTION_NAME;
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        final UpdateTIFJobRequest updateTIFJobRequest = new UpdateTIFJobRequest(request.param("name"));
        if (request.hasContentOrSourceParam()) {
            try (XContentParser parser = request.contentOrSourceParamParser()) {
                UpdateTIFJobRequest.PARSER.parse(parser, updateTIFJobRequest, null);
            }
        }
        return channel -> client.executeLocally(
            UpdateTIFJobAction.INSTANCE,
            updateTIFJobRequest,
            new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        String path = String.join("/", "/_plugins/_security_analytics", "threatintel/tifjob/{name}/_settings");
        return List.of(new Route(PUT, path));
    }
}
