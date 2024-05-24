package org.opensearch.securityanalytics.threatIntel.iocscan.dto;

import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.MonitorMetadata;
import org.opensearch.securityanalytics.threatIntel.model.monitor.ThreatIntelInput;

import java.util.List;
import java.util.Map;

public class IocScanContext<Data> {
    private final Monitor monitor;
    private final MonitorMetadata monitorMetadata;
    private final boolean dryRun;
    private final List<Data> data;
    private final ThreatIntelInput threatIntelInput; // deserialize threat intel input
    private final List<String> indices; // user's log data indices
    private final Map<String, List<String>> iocTypeToIndices;
    public IocScanContext(Monitor monitor, MonitorMetadata monitorMetadata, boolean dryRun, List<Data> data, ThreatIntelInput threatIntelInput, List<String> indices, Map<String, List<String>> iocTypeToIndices) {
        this.monitor = monitor;
        this.monitorMetadata = monitorMetadata;
        this.dryRun = dryRun;
        this.data = data;
        this.threatIntelInput = threatIntelInput;
        this.indices = indices;
        this.iocTypeToIndices = iocTypeToIndices;
    }

    public Monitor getMonitor() {
        return monitor;
    }

    public boolean isDryRun() {
        return dryRun;
    }

    public List<Data> getData() {
        return data;
    }

    public MonitorMetadata getMonitorMetadata() {
        return monitorMetadata;
    }

    public ThreatIntelInput getThreatIntelInput() {
        return threatIntelInput;
    }

    public List<String> getIndices() {
        return indices;
    }

    public Map<String, List<String>> getIocTypeToIndices() {
        return iocTypeToIndices;
    }
}
