package org.opensearch.securityanalytics.threatIntel.iocscan.service;

import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Trigger;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.threatIntel.model.monitor.ThreatIntelTrigger;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * context that stores information for sending threat intel monitor notification.
 * It is available to use in Threat intel monitor runner in mustache template.
 */

public class ThreatIntelAlertContext {
    public static final String MONITOR_FIELD = "monitor";
    public static final String NEW_ALERTS_FIELD = "new_alerts";
    public static final String EXISTING_ALERTS_FIELD = "existing_alerts";

    private final List<String> dataSources;
    private final List<String> iocTypes;
    private final String triggerName;
    private final String triggerId;
    private final List<ThreatIntelAlert> newAlerts;
    private final List<ThreatIntelAlert> existingAlerts;
    private final String severity;
    private final List<IocFinding> findingIds;
    private final Monitor monitor;

    public ThreatIntelAlertContext(ThreatIntelTrigger threatIntelTrigger, Trigger trigger, List<IocFinding> findingIds, Monitor monitor, List<ThreatIntelAlert> newAlerts, List<ThreatIntelAlert> existingAlerts) {
        this.dataSources = threatIntelTrigger.getDataSources();
        this.iocTypes = threatIntelTrigger.getIocTypes();
        this.triggerName = trigger.getName();
        this.triggerId = trigger.getId();
        this.newAlerts = newAlerts;
        this.existingAlerts = existingAlerts;
        this.severity = triggerId;
        this.findingIds = findingIds;
        this.monitor = monitor;
    }

    //cannot add trigger as Remote Trigger holds bytereference of object and not object itself
    public Map<String, Object> asTemplateArg() {
        return Map.of(
                ThreatIntelTrigger.DATA_SOURCES, dataSources,
                ThreatIntelTrigger.IOC_TYPES, iocTypes,
                Trigger.NAME_FIELD, triggerName,
                Trigger.ID_FIELD, triggerId,
                Trigger.SEVERITY_FIELD, severity,
                Alert.FINDING_IDS, findingIds.stream().map(IocFinding::asTemplateArg).collect(Collectors.toList()),
                MONITOR_FIELD, monitor.asTemplateArg(),
                NEW_ALERTS_FIELD, newAlerts.stream().map(ThreatIntelAlert::asTemplateArg).collect(Collectors.toList()),
                EXISTING_ALERTS_FIELD, existingAlerts.stream().map(ThreatIntelAlert::asTemplateArg).collect(Collectors.toList())
        );
    }
}
