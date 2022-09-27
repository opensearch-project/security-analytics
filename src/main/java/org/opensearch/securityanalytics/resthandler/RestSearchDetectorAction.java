/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.search.SearchHit;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.search.builder.SearchSourceBuilder;

import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Locale;
import org.json.JSONObject;
import org.json.JSONArray;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.rest.RestStatus.OK;

import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;

import static org.opensearch.securityanalytics.util.RestHandlerUtils._ID;
import static org.opensearch.securityanalytics.util.RestHandlerUtils._VERSION;

public class RestSearchDetectorAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestSearchDetectorAction.class);

    @Override
    public String getName() {
        return "search_detector_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(POST, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + "_search")
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + "_search"));

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.parseXContent(request.contentOrSourceParamParser());
        searchSourceBuilder.fetchSource(FetchSourceContext.parseFromRestRequest(request));
        searchSourceBuilder.seqNoAndPrimaryTerm(true);
        searchSourceBuilder.version(true);

        SearchRequest searchRequest = new SearchRequest();
        searchRequest.source(searchSourceBuilder);
        searchRequest.indices(Detector.DETECTORS_INDEX);

        return channel -> {
            client.search(searchRequest, new RestSearchDetectorResponseListener(channel, request));
        };
    }

    static class RestSearchDetectorResponseListener extends RestResponseListener<SearchResponse> {
        private final RestRequest request;

        RestSearchDetectorResponseListener(RestChannel channel, RestRequest request) {
            super(channel);
            this.request = request;
        }

        @Override
        public RestResponse buildResponse(final SearchResponse response) throws Exception {
            JSONArray jsonArray= new JSONArray();
            for (SearchHit hit : response.getHits()) {
                JSONObject jsonObject = new JSONObject(hit.getSourceAsString());
                jsonObject.put(_ID, hit.getId());
                jsonObject.put(_VERSION, hit.getVersion());
                jsonArray.put(jsonObject);
            }
            JSONObject returnObject = new JSONObject();
            // ToDo add the string "detectors" to Detector class.
            returnObject.put("detectors", jsonArray);
            return new BytesRestResponse(OK,returnObject.toString());
        }

    }
}