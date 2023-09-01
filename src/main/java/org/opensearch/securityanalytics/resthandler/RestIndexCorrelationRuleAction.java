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
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.action.RestResponseListener;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleAction;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleRequest;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleResponse;
import org.opensearch.securityanalytics.model.CorrelationRule;

public class RestIndexCorrelationRuleAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestIndexCorrelationRuleAction.class);

    @Override
    public String getName() {
        return "index_correlation_rule_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI),
            new Route(RestRequest.Method.PUT, String.format(Locale.getDefault(),
                    "%s/{%s}",
                    SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI,
                    "correlation_rule_id"))
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.ROOT, "%s %s", request.method(), SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI));

        String id = request.param("correlation_rule_id", CorrelationRule.NO_ID);

        XContentParser xcp = request.contentParser();

        CorrelationRule correlationRule = CorrelationRule.parse(xcp, id, null);
        IndexCorrelationRuleRequest indexCorrelationRuleRequest = new IndexCorrelationRuleRequest(id, correlationRule, request.method());
        return channel -> client.execute(
            IndexCorrelationRuleAction.INSTANCE,
            indexCorrelationRuleRequest,
            indexCorrelationRuleResponse(channel, request.method())
        );
    }

    private RestResponseListener<IndexCorrelationRuleResponse> indexCorrelationRuleResponse(
        RestChannel channel,
        RestRequest.Method restMethod
    ) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(IndexCorrelationRuleResponse response) throws Exception {
                RestStatus returnStatus = RestStatus.CREATED;
                if (restMethod == RestRequest.Method.PUT) {
                    returnStatus = RestStatus.OK;
                }

                BytesRestResponse restResponse = new BytesRestResponse(
                    returnStatus,
                    response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS)
                );

                if (restMethod == RestRequest.Method.POST) {
                    String location = String.format(
                        Locale.ROOT,
                        "%s/%s",
                        SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI,
                        response.getId()
                    );
                    restResponse.addHeader("Location", location);
                }

                return restResponse;
            }
        };
    }
}
