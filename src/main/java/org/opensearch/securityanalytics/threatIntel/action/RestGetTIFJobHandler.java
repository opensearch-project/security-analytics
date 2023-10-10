/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.common.Strings;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import java.util.List;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * Rest handler for tif job get request
 */
public class RestGetTIFJobHandler extends BaseRestHandler {
    private static final String ACTION_NAME = "threatintel_tifjob_get";

    @Override
    public String getName() {
        return ACTION_NAME;
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) {
        final String[] names = request.paramAsStringArray("name", Strings.EMPTY_ARRAY);
        final GetTIFJobRequest getTIFJobRequest = new GetTIFJobRequest(names);

        return channel -> client.executeLocally(GetTIFJobAction.INSTANCE, getTIFJobRequest, new RestToXContentListener<>(channel));
    }

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, String.join("/", "/_plugins/_security_analytics", "threatintel/tifjob")),
            new Route(GET, String.join("/", "/_plugins/_security_analytics", "threatintel/tifjob/{name}"))
        );
    }
}
