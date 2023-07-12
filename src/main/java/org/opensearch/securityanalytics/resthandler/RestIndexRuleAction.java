/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.RestStatus;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.IndexRuleAction;
import org.opensearch.securityanalytics.action.IndexRuleRequest;
import org.opensearch.securityanalytics.action.IndexRuleResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.util.RestHandlerUtils;

import java.util.List;
import java.util.Locale;

import static org.opensearch.securityanalytics.model.Detector.NO_ID;

public class RestIndexRuleAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestIndexRuleAction.class);

    @Override
    public String getName() {
        return "index_rule_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.RULE_BASE_URI),
                new Route(RestRequest.Method.PUT, SecurityAnalyticsPlugin.RULE_BASE_URI + "/{ruleID}")
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.RULE_BASE_URI));

        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.IMMEDIATE;
        if (request.hasParam(RestHandlerUtils.REFRESH)) {
            refreshPolicy = WriteRequest.RefreshPolicy.parse(request.param(RestHandlerUtils.REFRESH));
        }

        String id = request.param("ruleID", Detector.NO_ID);

        String category = request.param("category");
        if (category == null) {
            throw new IllegalArgumentException("Missing category");
        }

        Boolean forced = request.paramAsBoolean("forced", false);

        String rule = request.content().utf8ToString();

        IndexRuleRequest ruleRequest = new IndexRuleRequest(id, refreshPolicy, category, request.method(), rule, forced);
        return channel -> client.execute(IndexRuleAction.INSTANCE, ruleRequest, indexRuleResponse(channel, request.method()));
    }

    private RestResponseListener<IndexRuleResponse> indexRuleResponse(RestChannel channel, RestRequest.Method restMethod) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(IndexRuleResponse response) throws Exception {
                RestStatus returnStatus = RestStatus.CREATED;
                if (restMethod == RestRequest.Method.PUT) {
                    returnStatus = RestStatus.OK;
                }

                BytesRestResponse restResponse = new BytesRestResponse(returnStatus, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));

                if (restMethod == RestRequest.Method.POST) {
                    String location = String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.RULE_BASE_URI, response.getId());
                    restResponse.addHeader("Location", location);
                }

                return restResponse;
            }
        };
    }
}