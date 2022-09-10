/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.RestStatus;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.util.RestHandlerUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

public class RestIndexDetectorAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestIndexDetectorAction.class);

    @Override
    public String getName() {
        return "index_rules_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.DETECTOR_BASE_URI)
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.DETECTOR_BASE_URI));

        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.IMMEDIATE;
        if (request.hasParam(RestHandlerUtils.REFRESH)) {
            refreshPolicy = WriteRequest.RefreshPolicy.parse(request.param(RestHandlerUtils.REFRESH));
        }

        String id = request.param("detectorID", Detector.NO_ID);

        XContentParser xcp = request.contentParser();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);

        Detector detector = Detector.parse(xcp, id, null);
        detector.setLastUpdateTime(Instant.now());

        IndexDetectorRequest indexRulesRequest = new IndexDetectorRequest(id, refreshPolicy, request.method(), detector);
        return channel -> client.execute(IndexDetectorAction.INSTANCE, indexRulesRequest, indexRulesResponse(channel, request.method()));
    }

    private RestResponseListener<IndexDetectorResponse> indexRulesResponse(RestChannel channel, RestRequest.Method restMethod) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(IndexDetectorResponse response) throws Exception {
                RestStatus returnStatus = RestStatus.CREATED;

                BytesRestResponse restResponse = new BytesRestResponse(returnStatus, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
                String location = String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, response.getId());
                restResponse.addHeader("Location", location);

                return restResponse;
            }
        };
    }
}