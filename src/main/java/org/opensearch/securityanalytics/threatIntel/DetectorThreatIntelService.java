package org.opensearch.securityanalytics.threatIntel;

import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


public class DetectorThreatIntelService {

    private final ThreatIntelFeedDataService threatIntelFeedDataService;

    public DetectorThreatIntelService(ThreatIntelFeedDataService threatIntelFeedDataService) {
        this.threatIntelFeedDataService = threatIntelFeedDataService;
    }

    /** Convert the feed data IOCs into query string query format to create doc level queries. */
//    public DocLevelQuery createDocLevelQueryFromThreatIntelList(
//            List<ThreatIntelFeedData> tifdList, String docLevelQueryId
//            ) {
//        Set<String> iocs = tifdList.stream().map(ThreatIntelFeedData::getIocValue).collect(Collectors.toSet());
//        String query = buildQueryStringQueryWithIocList(iocs);
//        return new DocLevelQuery(
//                docLevelQueryId,tifdList.get(0).getFeedId(), query,
//                Collections.singletonList("threat_intel")
//        );
//    }

    private String buildQueryStringQueryWithIocList(Set<String> iocs) {
        StringBuilder sb = new StringBuilder();

        for(String ioc : iocs) {
            if(sb.length() != 0) {
                sb.append(" ");
            }
            sb.append("(");
            sb.append(ioc);
            sb.append(")");
        }
        return sb.toString();
    }

    public DocLevelQuery createDocLevelQueryFromThreatIntel(Detector detector) {
        // for testing validation only.
        if(detector.getThreatIntelEnabled() ==false) {
            throw new SecurityAnalyticsException(
                    "trying to create threat intel feed queries when flag to use threat intel is disabled.",
                    RestStatus.FORBIDDEN, new IllegalArgumentException());

        }
        // TODO: plugin logic to run job for populating threat intel feed data
        /*threatIntelFeedDataService.getThreatIntelFeedData("ip_address", );*/
        return null;
    }
}
