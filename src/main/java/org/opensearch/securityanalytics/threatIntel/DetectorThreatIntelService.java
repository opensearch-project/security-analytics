package org.opensearch.securityanalytics.threatIntel;

import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


public class DetectorThreatIntelService {

    /** Convert the feed data IOCs into query string query format to create doc level queries. */
    public static DocLevelQuery createDocLevelQueryFromThreatIntelList(
            List<ThreatIntelFeedData> tifdList, String docLevelQueryId
            ) {
        Set<String> iocs = tifdList.stream().map(ThreatIntelFeedData::getIocValue).collect(Collectors.toSet());
        String query = buildQueryStringQueryWithIocList(iocs);
        return new DocLevelQuery(
                docLevelQueryId,tifdList.get(0).getFeedId(), query,
                Collections.singletonList("threat_intel")
        );
    }

    private static String buildQueryStringQueryWithIocList(Set<String> iocs) {
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
}
