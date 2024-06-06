package org.opensearch.securityanalytics.threatIntel.sacommons.monitor;

public interface IndexIocScanMonitorResponseInterface {
    String getId();

    ThreatIntelMonitorDto getIocScanMonitor();
}

