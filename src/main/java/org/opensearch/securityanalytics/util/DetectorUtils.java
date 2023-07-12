/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.apache.lucene.search.TotalHits;
import org.opensearch.action.ActionListener;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.aggregations.InternalAggregations;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.search.internal.InternalSearchResponse;
import org.opensearch.search.profile.SearchProfileShardResults;
import org.opensearch.search.suggest.Suggest;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class DetectorUtils {

    public static final String DETECTOR_TYPE_PATH = "detector.detector_type";
    public static final String DETECTOR_ID_FIELD = "detector_id";

    public static SearchResponse getEmptySearchResponse() {
        return new SearchResponse(new InternalSearchResponse(
                new SearchHits(new SearchHit[0], new TotalHits(0L, TotalHits.Relation.EQUAL_TO), 0.0f),
                InternalAggregations.from(Collections.emptyList()),
                new Suggest(Collections.emptyList()),
                new SearchProfileShardResults(Collections.emptyMap()), false, false, 0),
                "", 0, 0, 0, 0,
                ShardSearchFailure.EMPTY_ARRAY, SearchResponse.Clusters.EMPTY);
    }

    public static List<Detector> getDetectors(SearchResponse response, NamedXContentRegistry xContentRegistry) throws IOException {
        List<Detector> detectors = new LinkedList<>();
        for (SearchHit hit : response.getHits()) {
            XContentParser xcp = XContentType.JSON.xContent().createParser(
                    xContentRegistry,
                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString());
            Detector detector = Detector.docParse(xcp, hit.getId(), hit.getVersion());
            detectors.add(detector);
        }
        return detectors;
    }

    public static void getAllDetectorInputs(Client client, NamedXContentRegistry xContentRegistry, ActionListener<Set<String>> actionListener) {

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.fetchSource(FetchSourceContext.FETCH_SOURCE);
        searchSourceBuilder.seqNoAndPrimaryTerm(true);
        searchSourceBuilder.version(true);

        SearchRequest searchRequest = new SearchRequest();
        searchRequest.source(searchSourceBuilder);
        searchRequest.indices(Detector.DETECTORS_INDEX);

        client.search(searchRequest, new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse response) {
                Set<String> allDetectorIndices = new HashSet<>();
                try {
                    List<Detector> detectors = DetectorUtils.getDetectors(response, xContentRegistry);
                    for (Detector detector : detectors) {
                        for (DetectorInput input : detector.getInputs()) {
                            allDetectorIndices.addAll(input.getIndices());
                        }
                    }
                } catch (IOException e) {
                    actionListener.onFailure(e);
                }
                actionListener.onResponse(allDetectorIndices);
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }
}