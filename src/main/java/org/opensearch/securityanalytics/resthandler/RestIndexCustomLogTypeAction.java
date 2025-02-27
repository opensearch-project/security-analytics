/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeAction;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeRequest;
import org.opensearch.securityanalytics.action.IndexCustomLogTypeResponse;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.util.RestHandlerUtils;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

public class RestIndexCustomLogTypeAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestIndexCustomLogTypeAction.class);

    @Override
    public String getName() {
        return "index_custom_log_type_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI),
                new Route(RestRequest.Method.PUT, String.format(Locale.getDefault(),
                        "%s/{%s}",
                        SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI,
                        CustomLogType.CUSTOM_LOG_TYPE_ID_FIELD))
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI));

        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.IMMEDIATE;
        if (request.hasParam(RestHandlerUtils.REFRESH)) {
            refreshPolicy = WriteRequest.RefreshPolicy.parse(request.param(RestHandlerUtils.REFRESH));
        }

        String id = request.param(CustomLogType.CUSTOM_LOG_TYPE_ID_FIELD, Detector.NO_ID);

        XContentParser xcp = request.contentParser();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);

        CustomLogType logType = CustomLogType.parse(xcp, id, null);
        IndexCustomLogTypeRequest customLogTypeRequest = new IndexCustomLogTypeRequest(id, refreshPolicy, request.method(), logType);
        return channel -> client.execute(IndexCustomLogTypeAction.INSTANCE, customLogTypeRequest, indexCustomLogTypeResponse(channel, request.method()));
    }

    private RestResponseListener<IndexCustomLogTypeResponse> indexCustomLogTypeResponse(RestChannel channel, RestRequest.Method restMethod) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(IndexCustomLogTypeResponse response) throws Exception {
                RestStatus returnStatus = RestStatus.CREATED;
                if (restMethod == RestRequest.Method.PUT) {
                    returnStatus = RestStatus.OK;
                }

                BytesRestResponse restResponse = new BytesRestResponse(returnStatus, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));

                if (restMethod == RestRequest.Method.POST) {
                    String location = String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, response.getId());
                    restResponse.addHeader("Location", location);
                }

                return restResponse;
            }
        };
    }
}