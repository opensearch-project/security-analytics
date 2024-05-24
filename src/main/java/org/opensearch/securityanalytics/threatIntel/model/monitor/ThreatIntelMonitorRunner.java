package org.opensearch.securityanalytics.threatIntel.model.monitor;

import org.opensearch.action.ActionType;

import org.opensearch.alerting.spi.RemoteMonitorRunner;
import org.opensearch.commons.alerting.action.DocLevelMonitorFanOutResponse;

public class ThreatIntelMonitorRunner extends RemoteMonitorRunner {

    public static final String THREAT_INTEL_MONITOR_ACTION_NAME = "cluster:admin/opensearch/security_analytics/threatIntel/monitor/fanout";
    public static final String FAN_OUT_ACTION_NAME = "cluster:admin/security_analytics/threatIntel/monitor/fanout";
    public static final String THREAT_INTEL_MONITOR_TYPE = "ti_doc_level_monitor";

    public static final String SAMPLE_REMOTE_DOC_LEVEL_MONITOR_RUNNER_INDEX = ".opensearch-alerting-sample-remote-doc-level-monitor";

    public static final ActionType<DocLevelMonitorFanOutResponse> REMOTE_DOC_LEVEL_MONITOR_ACTION_INSTANCE = new ActionType<>(FAN_OUT_ACTION_NAME,
            DocLevelMonitorFanOutResponse::new);

    private static ThreatIntelMonitorRunner INSTANCE;

    public static ThreatIntelMonitorRunner getMonitorRunner() {
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (ThreatIntelMonitorRunner.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new ThreatIntelMonitorRunner();
            return INSTANCE;
        }
    }

    @Override
    public String getFanOutAction() {
        return FAN_OUT_ACTION_NAME;
    }
}