package org.opensearch.securityanalytics.threatIntel.action.monitor;

import org.opensearch.action.ActionType;
import org.opensearch.securityanalytics.threatIntel.action.monitor.response.IndexThreatIntelMonitorResponse;

import static org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorActions.INDEX_THREAT_INTEL_MONITOR_ACTION_NAME;


public class IndexThreatIntelMonitorAction extends ActionType<IndexThreatIntelMonitorResponse> {

    public static final IndexThreatIntelMonitorAction INSTANCE = new IndexThreatIntelMonitorAction();
    public static final String NAME = INDEX_THREAT_INTEL_MONITOR_ACTION_NAME;

    private IndexThreatIntelMonitorAction() {
        super(NAME, IndexThreatIntelMonitorResponse::new);
    }
}
