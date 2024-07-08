package org.opensearch.securityanalytics.threatIntel.action.monitor;

import org.opensearch.action.ActionType;
import org.opensearch.commons.alerting.action.DeleteMonitorResponse;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorActions;

public class DeleteThreatIntelMonitorAction extends ActionType<DeleteMonitorResponse> {

    public static final DeleteThreatIntelMonitorAction INSTANCE = new DeleteThreatIntelMonitorAction();
    public static final String NAME = ThreatIntelMonitorActions.DELETE_THREAT_INTEL_MONITOR_ACTION_NAME;

    private DeleteThreatIntelMonitorAction() {
        super(NAME, DeleteMonitorResponse::new);
    }
}
