/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.action;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.common.Strings;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import java.util.List;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * Rest handler for threat intel datasource get request
 */
public class RestGetDatasourceHandler extends BaseRestHandler {
    private static final String ACTION_NAME = "threatintel_datasource_get";

    @Override
    public String getName() {
        return ACTION_NAME;
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) {
        final String[] names = request.paramAsStringArray("name", Strings.EMPTY_ARRAY);
        final GetDatasourceRequest getDatasourceRequest = new GetDatasourceRequest(names);

        return channel -> client.executeLocally(GetDatasourceAction.INSTANCE, getDatasourceRequest, new RestToXContentListener<>(channel));
    }

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(GET, String.join("/", "/_plugins/_security_analytics", "threatintel/datasource")),
            new Route(GET, String.join("/", "/_plugins/_security_analytics", "threatintel/datasource/{name}"))
        );
    }
}
