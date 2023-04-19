/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.ListCorrelationsAction;
import org.opensearch.securityanalytics.action.ListCorrelationsRequest;
import org.opensearch.securityanalytics.action.ListCorrelationsResponse;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestStatus.OK;

public class RestListCorrelationAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestListCorrelationAction.class);

    @Override
    public String getName() {
        return "list_correlation_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(GET, SecurityAnalyticsPlugin.LIST_CORRELATIONS_URI)
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.ROOT, "%s %s", request.method(), SecurityAnalyticsPlugin.LIST_CORRELATIONS_URI));

        Long defaultTimestamp = System.currentTimeMillis();
        Long startTimestamp = request.paramAsLong("start_timestamp", defaultTimestamp - 300000L);
        Long endTimestamp = request.paramAsLong("end_timestamp", defaultTimestamp);

        ListCorrelationsRequest correlationsRequest = new ListCorrelationsRequest(startTimestamp, endTimestamp);
        return channel -> {
            client.execute(ListCorrelationsAction.INSTANCE, correlationsRequest, new RestListCorrelationAction.RestListCorrelationResponseListener(channel, request));
        };
    }

    static class RestListCorrelationResponseListener extends RestResponseListener<ListCorrelationsResponse> {
        private final RestRequest request;

        RestListCorrelationResponseListener(RestChannel channel, RestRequest request) {
            super(channel);
            this.request = request;
        }

        @Override
        public RestResponse buildResponse(final ListCorrelationsResponse response) throws Exception {
            return new BytesRestResponse(OK, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
        }

    }
}