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
import org.opensearch.rest.*;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.IndexRulesAction;
import org.opensearch.securityanalytics.action.IndexRulesRequest;
import org.opensearch.securityanalytics.action.IndexRulesResponse;
import org.opensearch.securityanalytics.util.RestHandlerUtils;

import java.io.IOException;
import java.util.*;

public class RestIndexRulesAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestIndexRulesAction.class);

    @Override
    public String getName() {
        return "index_rules_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.RULES_BASE_URI)
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.RULES_BASE_URI));

        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.IMMEDIATE;
        if (request.hasParam(RestHandlerUtils.REFRESH)) {
            refreshPolicy = WriteRequest.RefreshPolicy.parse(request.param(RestHandlerUtils.REFRESH));
        }

        String rule = "";
        if (request.method() == RestRequest.Method.PUT) {
            rule = request.content().utf8ToString();
        }

        String ruleTopic = request.param(RestHandlerUtils.RULE_TOPIC);
        if (ruleTopic == null || ruleTopic.isEmpty()) {
            throw new IllegalArgumentException(RestHandlerUtils.RULE_TOPIC + " is empty");
        }

        IndexRulesRequest indexRulesRequest = new IndexRulesRequest(refreshPolicy, ruleTopic, rule, request.method());
        return channel -> client.execute(IndexRulesAction.INSTANCE, indexRulesRequest, indexRulesResponse(channel, request.method()));
    }

    private RestResponseListener<IndexRulesResponse> indexRulesResponse(RestChannel channel, RestRequest.Method restMethod) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(IndexRulesResponse response) throws Exception {
                RestStatus returnStatus = RestStatus.CREATED;

                return new BytesRestResponse(returnStatus, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
            }
        };
    }
}