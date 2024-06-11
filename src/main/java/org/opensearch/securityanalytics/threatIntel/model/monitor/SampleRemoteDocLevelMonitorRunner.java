package org.opensearch.securityanalytics.threatIntel.model.monitor;

import org.opensearch.action.ActionType;

import org.opensearch.alerting.spi.RemoteMonitorRunner;
import org.opensearch.commons.alerting.action.DocLevelMonitorFanOutResponse;

public class SampleRemoteDocLevelMonitorRunner extends RemoteMonitorRunner {

    public static final String REMOTE_DOC_LEVEL_MONITOR_ACTION_NAME = "cluster:admin/opensearch/alerting/remote_monitor/fanout";

    public static final String SAMPLE_REMOTE_DOC_LEVEL_MONITOR_RUNNER_INDEX = ".opensearch-alerting-sample-remote-doc-level-monitor";

    public static final ActionType<DocLevelMonitorFanOutResponse> REMOTE_DOC_LEVEL_MONITOR_ACTION_INSTANCE = new ActionType<>(REMOTE_DOC_LEVEL_MONITOR_ACTION_NAME,
            DocLevelMonitorFanOutResponse::new);

    private static SampleRemoteDocLevelMonitorRunner INSTANCE;

    public static SampleRemoteDocLevelMonitorRunner getMonitorRunner() {
        if (INSTANCE != null) {
            return INSTANCE;
        }
        synchronized (SampleRemoteDocLevelMonitorRunner.class) {
            if (INSTANCE != null) {
                return INSTANCE;
            }
            INSTANCE = new SampleRemoteDocLevelMonitorRunner();
            return INSTANCE;
        }
    }

    @Override
    public String getFanOutAction() {
        return REMOTE_DOC_LEVEL_MONITOR_ACTION_NAME;
    }
}