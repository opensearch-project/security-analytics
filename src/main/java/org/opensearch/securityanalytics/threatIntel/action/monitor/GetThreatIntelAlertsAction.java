package org.opensearch.securityanalytics.threatIntel.action.monitor;

import org.opensearch.action.ActionType;
import org.opensearch.securityanalytics.threatIntel.action.monitor.response.GetThreatIntelAlertsResponse;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorActions;

public class GetThreatIntelAlertsAction extends ActionType<GetThreatIntelAlertsResponse> {

    public static final GetThreatIntelAlertsAction INSTANCE = new GetThreatIntelAlertsAction();
    public static final String NAME = ThreatIntelMonitorActions.GET_THREAT_INTEL_ALERTS_ACTION_NAME;

    public GetThreatIntelAlertsAction() {
        super(NAME, GetThreatIntelAlertsResponse::new);
    }
}
