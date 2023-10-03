/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.action;

import org.opensearch.client.node.NodeClient;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.threatintel.common.ThreatIntelSettings;

import java.io.IOException;
import java.util.List;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * Rest handler for threat intel datasource creation
 *
 * This handler handles a request of
 * PUT /_plugins/security_analytics/threatintel/datasource/{id}
 * {
 *     "endpoint": {endpoint},
 *     "update_interval_in_days": 3
 * }
 *
 * When request is received, it will create a datasource by downloading threat intel feed from the endpoint.
 * After the creation of datasource is completed, it will schedule the next update task after update_interval_in_days.
 *
 */
public class RestPutDatasourceHandler extends BaseRestHandler {
    private static final String ACTION_NAME = "threatintel_datasource_put";
    private final ClusterSettings clusterSettings;

    public RestPutDatasourceHandler(final ClusterSettings clusterSettings) {
        this.clusterSettings = clusterSettings;
    }

    @Override
    public String getName() {
        return ACTION_NAME;
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        final PutDatasourceRequest putDatasourceRequest = new PutDatasourceRequest(request.param("name"));
        if (request.hasContentOrSourceParam()) {
            try (XContentParser parser = request.contentOrSourceParamParser()) {
                PutDatasourceRequest.PARSER.parse(parser, putDatasourceRequest, null);
            }
        }
        if (putDatasourceRequest.getEndpoint() == null) {
            putDatasourceRequest.setEndpoint(clusterSettings.get(ThreatIntelSettings.DATASOURCE_ENDPOINT));
        }
        if (putDatasourceRequest.getUpdateInterval() == null) {
            putDatasourceRequest.setUpdateInterval(TimeValue.timeValueDays(clusterSettings.get(ThreatIntelSettings.DATASOURCE_UPDATE_INTERVAL)));
        }
        return channel -> client.executeLocally(PutDatasourceAction.INSTANCE, putDatasourceRequest, new RestToXContentListener<>(channel));
    }

    @Override
    public List<Route> routes() {
        String path = String.join("/", "/_plugins/_security_analytics", "threatintel/datasource/{name}");
        return List.of(new Route(PUT, path));
    }
}
