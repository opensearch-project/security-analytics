/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.SearchDetectorAction;
import org.opensearch.securityanalytics.action.SearchDetectorRequest;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.LogType;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.model.Detector.DETECTORS_INDEX;
import static org.opensearch.securityanalytics.util.DetectorUtils.getDetectors;

/**
 * Service that populates detectors with queries generated from threat intelligence data.
 */
public class DetectorThreatIntelService {

    private static final Logger log = LogManager.getLogger(DetectorThreatIntelService.class);

    private final ThreatIntelFeedDataService threatIntelFeedDataService;
    private final Client client;
    private final NamedXContentRegistry xContentRegistry;

    public DetectorThreatIntelService(ThreatIntelFeedDataService threatIntelFeedDataService, Client client, NamedXContentRegistry xContentRegistry) {
        this.threatIntelFeedDataService = threatIntelFeedDataService;
        this.client = client;
        this.xContentRegistry = xContentRegistry;
    }


    /**
     * Convert the feed data IOCs into query string query format to create doc level queries.
     */
    public List<DocLevelQuery> createDocLevelQueriesFromThreatIntelList(
            List<LogType.IocFields> iocFieldList, List<ThreatIntelFeedData> tifdList, Detector detector
    ) {
        List<DocLevelQuery> queries = new ArrayList<>();
        Set<String> iocs = tifdList.stream().map(ThreatIntelFeedData::getIocValue).collect(Collectors.toSet());
        //ioc types supported by log type
        List<String> logTypeIocs = iocFieldList.stream().map(LogType.IocFields::getIoc).collect(Collectors.toList());
        // filter out ioc types not supported for given log types
        Map<String, Set<String>> iocTypeToValues = tifdList.stream().filter(t -> logTypeIocs.contains(t.getIocType()))
                .collect(Collectors.groupingBy(
                        ThreatIntelFeedData::getIocType,
                        Collectors.mapping(ThreatIntelFeedData::getIocValue, Collectors.toSet())
                ));

        for (Map.Entry<String, Set<String>> entry : iocTypeToValues.entrySet()) {
            String query = buildQueryStringQueryWithIocList(iocs);
            List<String> fields = iocFieldList.stream().filter(t -> entry.getKey().matches(t.getIoc())).findFirst().get().getFields();

            // create doc
            for (String field : fields) {
                queries.add(new DocLevelQuery(
                        constructId(detector, entry.getKey()), tifdList.get(0).getFeedId(),
                        Collections.emptyList(),
                        String.format(query, field),
                        List.of(
                                "threat_intel",
                                String.format("ioc_type:%s", entry.getKey()),
                                String.format("field:%s", field),
                                String.format("feed_name:%s", tifdList.get(0).getFeedId())
                        )
                ));
            }
        }
        return queries;
    }

    private String buildQueryStringQueryWithIocList(Set<String> iocs) {
        StringBuilder sb = new StringBuilder();
        sb.append("%s");
        sb.append(":");
        sb.append("(");
        for (String ioc : iocs) {
            if (sb.length() > 4) {
                sb.append(" OR ");
            }
            sb.append(ioc);

        }
        sb.append(")");
        return sb.toString();
    }

    /**
     * Fetches threat intel data and creates doc level queries from threat intel data
     */
    public void createDocLevelQueryFromThreatIntel(List<LogType.IocFields> iocFieldList, Detector detector, ActionListener<List<DocLevelQuery>> listener) {
            if (false == detector.getThreatIntelEnabled() || iocFieldList.isEmpty()) {
                listener.onResponse(Collections.emptyList());
                return;
            }
            threatIntelFeedDataService.getThreatIntelFeedData(new ActionListener<>() {
                @Override
                public void onResponse(List<ThreatIntelFeedData> threatIntelFeedData) {
                    if (threatIntelFeedData.isEmpty()) {
                        listener.onResponse(Collections.emptyList());
                    } else {
                        listener.onResponse(
                                createDocLevelQueriesFromThreatIntelList(iocFieldList, threatIntelFeedData, detector)
                        );
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to get threat intel feeds for doc level query creation", e);
                    listener.onFailure(e);
                }
            });
    }

    private static String constructId(Detector detector, String iocType) {
        return "threat_intel_" + UUID.randomUUID();
    }

    /** Updates all detectors having threat intel detection enabled with the latest threat intel feed data*/
    public void updateDetectorsWithLatestThreatIntelRules() {
            QueryBuilder queryBuilder =
                    QueryBuilders.nestedQuery("detector",
                            QueryBuilders.boolQuery().must(
                                    QueryBuilders.matchQuery("detector.threat_intel_enabled", true)
                            ), ScoreMode.Avg);
            SearchRequest searchRequest = new SearchRequest(DETECTORS_INDEX);
            SearchSourceBuilder ssb = searchRequest.source();
            ssb.query(queryBuilder);
            ssb.size(9999);
            client.execute(SearchDetectorAction.INSTANCE, new SearchDetectorRequest(searchRequest),
                    ActionListener.wrap(searchResponse -> {
                        List<Detector> detectors = getDetectors(searchResponse, xContentRegistry);
                        detectors.forEach(detector -> {
                                    assert detector.getThreatIntelEnabled();
                                    client.execute(IndexDetectorAction.INSTANCE, new IndexDetectorRequest(
                                                    detector.getId(), WriteRequest.RefreshPolicy.IMMEDIATE,
                                                    RestRequest.Method.PUT,
                                                    detector),
                                            ActionListener.wrap(
                                                    indexDetectorResponse -> {
                                                        log.debug("updated {} with latest threat intel info", indexDetectorResponse.getDetector().getId());
                                                    },
                                                    e -> {
                                                        log.error(() -> new ParameterizedMessage("Failed to update detector {} with latest threat intel info", detector.getId()), e);
                                                    }));
                                }
                        );
                    }, e -> {
                        log.error("Failed to fetch detectors to update with threat intel queries.", e);
                    }));


    }
}
