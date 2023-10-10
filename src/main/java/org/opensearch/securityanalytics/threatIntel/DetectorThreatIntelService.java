package org.opensearch.securityanalytics.threatIntel;

import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;


public class DetectorThreatIntelService {

    private final ThreatIntelFeedDataService threatIntelFeedDataService;

    public DetectorThreatIntelService(ThreatIntelFeedDataService threatIntelFeedDataService) {
        this.threatIntelFeedDataService = threatIntelFeedDataService;
    }

    /**
     * Convert the feed data IOCs into query string query format to create doc level queries.
     */
    public DocLevelQuery createDocLevelQueryFromThreatIntelList(
            List<ThreatIntelFeedData> tifdList, String docLevelQueryId
    ) {
        Set<String> iocs = tifdList.stream().map(ThreatIntelFeedData::getIocValue).collect(Collectors.toSet());
        String query = buildQueryStringQueryWithIocList(iocs);
        return new DocLevelQuery(
                docLevelQueryId, tifdList.get(0).getFeedId(),
                Collections.singletonList("*"),
                query,
                Collections.singletonList("threat_intel")
        );
    }

    private String buildQueryStringQueryWithIocList(Set<String> iocs) {
        StringBuilder sb = new StringBuilder();
        sb.append("(");
        for (String ioc : iocs) {
            if (sb.length() > 2) {
                sb.append(" OR ");
            }
            sb.append(ioc);

        }
        sb.append(")");
        return sb.toString();
    }

    public void createDocLevelQueryFromThreatIntel(Detector detector, ActionListener<DocLevelQuery> listener) {
        try {
            if (detector.getThreatIntelEnabled() == false) {
                listener.onResponse(null);
                return;

            }
            CountDownLatch latch = new CountDownLatch(1);
            // TODO: plugin logic to run job for populating threat intel feed data
            //TODO populateFeedData()
            threatIntelFeedDataService.getThreatIntelFeedData(new ActionListener<>() {
                @Override
                public void onResponse(List<ThreatIntelFeedData> threatIntelFeedData) {
                    if (threatIntelFeedData.isEmpty()) {
                        listener.onResponse(null);
                    } else {
                        listener.onResponse(createDocLevelQueryFromThreatIntelList(
                                threatIntelFeedData,
                                detector.getName() + "_threat_intel" + UUID.randomUUID()
                        ));
                    }
                    latch.countDown();
                }

                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
                    latch.countDown();
                }
            });

            latch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            listener.onFailure(e);
        }

    }

    public void updateDetectorsWithLatestThreatIntelRules() {

    }
}
