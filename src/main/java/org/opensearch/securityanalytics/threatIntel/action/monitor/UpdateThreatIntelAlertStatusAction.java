package org.opensearch.securityanalytics.threatIntel.action.monitor;

import org.opensearch.action.ActionType;
import org.opensearch.securityanalytics.threatIntel.action.monitor.response.UpdateThreatIntelAlertsStatusResponse;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorActions;

public class UpdateThreatIntelAlertStatusAction extends ActionType<UpdateThreatIntelAlertsStatusResponse> {

    public static final UpdateThreatIntelAlertStatusAction INSTANCE = new UpdateThreatIntelAlertStatusAction();
    public static final String NAME = ThreatIntelMonitorActions.UPDATE_THREAT_INTEL_ALERT_STATUS_ACTION_NAME;

    public UpdateThreatIntelAlertStatusAction() {
        super(NAME, UpdateThreatIntelAlertsStatusResponse::new);
    }
}
