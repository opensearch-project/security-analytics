package org.opensearch.securityanalytics.threatIntel.action.monitor;

import org.opensearch.action.ActionType;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorActions;

public class SearchThreatIntelMonitorAction extends ActionType<SearchResponse> {

    public static final SearchThreatIntelMonitorAction INSTANCE = new SearchThreatIntelMonitorAction();
    public static final String NAME = ThreatIntelMonitorActions.SEARCH_THREAT_INTEL_MONITOR_ACTION_NAME;

    private SearchThreatIntelMonitorAction() {
        super(NAME, SearchResponse::new);
    }
}