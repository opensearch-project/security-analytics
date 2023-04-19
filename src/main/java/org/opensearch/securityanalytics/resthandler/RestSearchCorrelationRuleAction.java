/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.SearchCorrelationRuleAction;
import org.opensearch.securityanalytics.action.SearchCorrelationRuleRequest;
import org.opensearch.securityanalytics.model.CorrelationRule;

public class RestSearchCorrelationRuleAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestSearchCorrelationRuleAction.class);

    @Override
    public String getName() {
        return "search_correlation_rule_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search")
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s/_search", request.method(), SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI));

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.parseXContent(request.contentOrSourceParamParser());
        searchSourceBuilder.fetchSource(null);

        QueryBuilder queryBuilder = QueryBuilders.boolQuery().must(searchSourceBuilder.query());

        searchSourceBuilder.query(queryBuilder)
                .seqNoAndPrimaryTerm(true)
                .version(true);
        SearchRequest searchRequest = new SearchRequest()
                .source(searchSourceBuilder)
                .indices(CorrelationRule.CORRELATION_RULE_INDEX);

        SearchCorrelationRuleRequest searchCorrelationRuleRequest = new SearchCorrelationRuleRequest(searchRequest);
        return channel -> client.execute(SearchCorrelationRuleAction.INSTANCE, searchCorrelationRuleRequest, new RestToXContentListener<>(channel));
    }

//    private RestResponseListener<SearchResponse> searchRuleResponse(RestChannel channel) {
//        return new RestResponseListener<>(channel) {
//            @Override
//            public RestResponse buildResponse(SearchResponse response) throws Exception {
//                if (response.isTimedOut()) {
//                    return new BytesRestResponse(RestStatus.REQUEST_TIMEOUT, response.toString());
//                }
//
//                try {
//                    for (SearchHit hit: response.getHits()) {
//                        XContentParser xcp = XContentType.JSON.xContent().createParser(
//                                channel.request().getXContentRegistry(),
//                                LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
//                        );
//
//                        Rule rule = Rule.docParse(xcp, hit.getId(), hit.getVersion());
//                        XContentBuilder xcb = rule.toXContent(XContentFactory.jsonBuilder(), EMPTY_PARAMS);
//                        hit.sourceRef(BytesReference.bytes(xcb));
//                    }
//                } catch (Exception ex) {
//                    log.info("The rule parsing failed. Will return response as is.");
//                }
//                return new BytesRestResponse(RestStatus.OK, response.toXContent(channel.newBuilder(), EMPTY_PARAMS));
//            }
//        };
//    }
}