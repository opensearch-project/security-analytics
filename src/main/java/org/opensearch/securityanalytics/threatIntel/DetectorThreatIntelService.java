/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.core.action.ActionListener;
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


public class DetectorThreatIntelService {

    private static final Logger log = LogManager.getLogger(DetectorThreatIntelService.class);

    private final ThreatIntelFeedDataService threatIntelFeedDataService;

    public DetectorThreatIntelService(ThreatIntelFeedDataService threatIntelFeedDataService) {
        this.threatIntelFeedDataService = threatIntelFeedDataService;
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
            for (String field : fields) { //todo increase max clause count from 1024
                queries.add(new DocLevelQuery(
                        constructId(detector, entry.getKey()), tifdList.get(0).getFeedId(),
                        Collections.emptyList(),
                        "windows-hostname:(120.85.114.146 OR 103.104.106.223 OR 185.191.246.45 OR 120.86.237.94)",
                        List.of("threat_intel", entry.getKey() /*ioc_type*/)
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

    public void createDocLevelQueryFromThreatIntel(List<LogType.IocFields> iocFieldList, Detector detector, ActionListener<List<DocLevelQuery>> listener) {
        try {
            if (false == detector.getThreatIntelEnabled() || iocFieldList.isEmpty()) {
                listener.onResponse(Collections.emptyList());
                return;
            }

            CountDownLatch latch = new CountDownLatch(1);
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
                    latch.countDown();
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to get threat intel feeds for doc level query creation", e);
                    listener.onFailure(e);
                    latch.countDown();
                }
            });

            latch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            log.error("Failed to create doc level queries from threat intel feeds", e);
            listener.onFailure(e);
        }

    }

    private static String constructId(Detector detector, String iocType) {
        return detector.getName() + "_threat_intel_" + iocType + "_" + UUID.randomUUID();
    }

    public void updateDetectorsWithLatestThreatIntelRules() {

    }
}
