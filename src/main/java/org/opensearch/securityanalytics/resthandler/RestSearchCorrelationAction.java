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
import org.opensearch.securityanalytics.action.CorrelatedFindingAction;
import org.opensearch.securityanalytics.action.CorrelatedFindingRequest;
import org.opensearch.securityanalytics.action.CorrelatedFindingResponse;
import org.opensearch.securityanalytics.model.Detector;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestStatus.OK;

public class RestSearchCorrelationAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestSearchCorrelationAction.class);

    @Override
    public String getName() {
        return "search_correlation_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(GET, SecurityAnalyticsPlugin.FINDINGS_CORRELATE_URI)
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.ROOT, "%s %s", request.method(), SecurityAnalyticsPlugin.FINDINGS_CORRELATE_URI));

        String findingId = request.param("finding");
        if (findingId == null) {
            throw new IllegalArgumentException("Missing finding");
        }

        String detectorType = request.param("detector_type");
        if (detectorType == null) {
            throw new IllegalArgumentException("Missing detectorType");
        }

        long timeWindow = request.paramAsLong("time_window", 300000L);
        int noOfNearbyFindings = request.paramAsInt("nearby_findings", 10);

        CorrelatedFindingRequest correlatedFindingRequest = new CorrelatedFindingRequest(findingId, Detector.DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)), timeWindow, noOfNearbyFindings);

        return channel -> {
            client.execute(CorrelatedFindingAction.INSTANCE, correlatedFindingRequest, new RestCorrelatedFindingResponseListener(channel, request));
        };
    }

    static class RestCorrelatedFindingResponseListener extends RestResponseListener<CorrelatedFindingResponse> {
        private final RestRequest request;

        RestCorrelatedFindingResponseListener(RestChannel channel, RestRequest request) {
            super(channel);
            this.request = request;
        }

        @Override
        public RestResponse buildResponse(final CorrelatedFindingResponse response) throws Exception {
            return new BytesRestResponse(OK, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
        }

    }
}