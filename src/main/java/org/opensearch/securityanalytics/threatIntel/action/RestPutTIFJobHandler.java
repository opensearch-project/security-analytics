/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.client.node.NodeClient;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;

import java.io.IOException;
import java.util.List;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * Rest handler for threat intel TIFjob creation
 *
 * This handler handles a request of
 * PUT /_plugins/security_analytics/threatintel/tifjob/{id}
 * {
 *     "name": {name},
 *     "update_interval_in_days": 1
 * }
 *
 * When request is received, it will create a TIFjob
 * After the creation of TIFjob is completed, it will schedule the next update task after update_interval_in_days.
 *
 */
public class RestPutTIFJobHandler extends BaseRestHandler {
    private static final String ACTION_NAME = "threatintel_tifjob_put";
    private final ClusterSettings clusterSettings;

    public RestPutTIFJobHandler(final ClusterSettings clusterSettings) {
        this.clusterSettings = clusterSettings;
    }

    @Override
    public String getName() {
        return ACTION_NAME;
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        final PutTIFJobRequest putTIFJobRequest = new PutTIFJobRequest(request.param("name"));
        if (request.hasContentOrSourceParam()) {
            try (XContentParser parser = request.contentOrSourceParamParser()) {
                PutTIFJobRequest.PARSER.parse(parser, putTIFJobRequest, null);
            }
        }
        if (putTIFJobRequest.getUpdateInterval() == null) {
            putTIFJobRequest.setUpdateInterval(TimeValue.timeValueDays(clusterSettings.get(SecurityAnalyticsSettings.TIFJOB_UPDATE_INTERVAL)));
        }
        return channel -> client.executeLocally(PutTIFJobAction.INSTANCE, putTIFJobRequest, new RestToXContentListener<>(channel));
    }

    @Override
    public List<Route> routes() {
        String path = String.join("/", "/_plugins/_security_analytics", "threatintel/tifjob/{name}");
        return List.of(new Route(PUT, path));
    }
}
