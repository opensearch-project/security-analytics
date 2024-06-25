/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.lucene.search.TotalHits;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.commons.alerting.action.IndexMonitorResponse;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.core.action.ActionListener;
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
import org.opensearch.securityanalytics.model.Rule;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class DetectorUtils {

    public static final String DETECTOR_TYPE_PATH = "detector.detector_type";
    public static final String DETECTOR_ID_FIELD = "detector_id";
    public static final String NO_DETECTORS_FOUND = "No detectors found ";
    public static final String NO_DETECTORS_FOUND_FOR_PROVIDED_TYPE = "No detectors found for provided type";
    public static final int MAX_DETECTORS_SEARCH_SIZE = 10000;

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
        searchRequest.preference(Preference.PRIMARY_FIRST.type());

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

    public static List<String> getBucketLevelMonitorIds(
            List<IndexMonitorResponse> monitorResponses
    ) {
        return monitorResponses.stream().filter(
                // In the case of bucket level monitors rule id is trigger id
                it -> Monitor.MonitorType.BUCKET_LEVEL_MONITOR.getValue() == it.getMonitor().getMonitorType()
                ).map(IndexMonitorResponse::getId).collect(Collectors.toList());
    }
    public static List<String> getAggRuleIdsConfiguredToTrigger(Detector detector, List<Pair<String, Rule>> rulesById) {
        Set<String> ruleIdsConfiguredToTrigger = detector.getTriggers().stream().flatMap(t -> t.getRuleIds().stream()).collect(Collectors.toSet());
        Set<String> tagsConfiguredToTrigger = detector.getTriggers().stream().flatMap(t -> t.getTags().stream()).collect(Collectors.toSet());
        return rulesById.stream()
                .filter(it -> checkIfRuleIsAggAndTriggerable( it.getRight(), ruleIdsConfiguredToTrigger, tagsConfiguredToTrigger))
                .map(stringRulePair -> stringRulePair.getRight().getId())
                .collect(Collectors.toList());
    }

    private static boolean checkIfRuleIsAggAndTriggerable(Rule rule, Set<String> ruleIdsConfiguredToTrigger, Set<String> tagsConfiguredToTrigger) {
        if (rule.isAggregationRule()) {
            return ruleIdsConfiguredToTrigger.contains(rule.getId())
                    || rule.getTags().stream().anyMatch(tag -> tagsConfiguredToTrigger.contains(tag.getValue()));
        }
        return false;
    }


}