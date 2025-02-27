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
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.SearchCustomLogTypeAction;
import org.opensearch.securityanalytics.action.SearchCustomLogTypeRequest;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.opensearch.core.rest.RestStatus.OK;

public class RestSearchCustomLogTypeAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestSearchCustomLogTypeAction.class);

    @Override
    public String getName() {
        return "search_custom_log_type_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + "_search"),
                new Route(RestRequest.Method.GET, SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + "_search")
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + "_search"));

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.parseXContent(request.contentOrSourceParamParser());
        searchSourceBuilder.fetchSource(FetchSourceContext.parseFromRestRequest(request));
        searchSourceBuilder.seqNoAndPrimaryTerm(true);
        searchSourceBuilder.version(true);

        SearchRequest searchRequest = new SearchRequest();
        searchRequest.source(searchSourceBuilder);
        searchRequest.indices(LogTypeService.LOG_TYPE_INDEX);

        SearchCustomLogTypeRequest searchCustomLogTypeRequest = new SearchCustomLogTypeRequest(searchRequest);
        return channel -> {
            client.execute(SearchCustomLogTypeAction.INSTANCE, searchCustomLogTypeRequest, new RestSearchCustomLogTypeResponseListener(channel, request));
        };
    }

    static class RestSearchCustomLogTypeResponseListener extends RestResponseListener<SearchResponse> {
        private final RestRequest request;

        RestSearchCustomLogTypeResponseListener(RestChannel channel, RestRequest request) {
            super(channel);
            this.request = request;
        }

        @Override
        public RestResponse buildResponse(final SearchResponse response) throws Exception {
            for (SearchHit hit : response.getHits()) {
                Map<String, Object> sourceMap = hit.getSourceAsMap();

                CustomLogType logType = new CustomLogType(sourceMap);
                logType.setId(hit.getId());
                logType.setVersion(hit.getVersion());

                XContentBuilder xcb = logType.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS);
                hit.sourceRef(BytesReference.bytes(xcb));
            }
            return new BytesRestResponse(OK, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
        }

    }
}