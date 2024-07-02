package org.opensearch.securityanalytics.threatIntel.util;

import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Trigger;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteDocLevelMonitorInput;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteMonitorTrigger;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.PerIocTypeScanInputDto;
import org.opensearch.securityanalytics.threatIntel.model.monitor.ThreatIntelInput;
import org.opensearch.securityanalytics.threatIntel.model.monitor.ThreatIntelTrigger;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelTriggerDto;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.util.XContentUtils.getBytesReference;

public class ThreatIntelMonitorUtils {
    public static RemoteMonitorTrigger buildRemoteMonitorTrigger(ThreatIntelTriggerDto trigger) throws IOException {
        return new RemoteMonitorTrigger(trigger.getId(), trigger.getName(), trigger.getSeverity(), trigger.getActions(),
                getBytesReference(new ThreatIntelTrigger(trigger.getDataSources(), trigger.getIocTypes())));
    }

    public static List<ThreatIntelTriggerDto> buildThreatIntelTriggerDtos(List<Trigger> triggers, NamedXContentRegistry namedXContentRegistry) throws IOException {

        List<ThreatIntelTriggerDto> triggerDtos = new ArrayList<>();
        for (Trigger trigger : triggers) {
            RemoteMonitorTrigger remoteMonitorTrigger = (RemoteMonitorTrigger) trigger;
            ThreatIntelTrigger threatIntelTrigger = getThreatIntelTriggerFromBytesReference(remoteMonitorTrigger, namedXContentRegistry);

            triggerDtos.add(new ThreatIntelTriggerDto(
                    threatIntelTrigger.getDataSources(),
                    threatIntelTrigger.getIocTypes(),
                    remoteMonitorTrigger.getActions(),
                    remoteMonitorTrigger.getName(),
                    remoteMonitorTrigger.getId(),
                    remoteMonitorTrigger.getSeverity()
            ));
        }
        return triggerDtos;
    }

    public static ThreatIntelTrigger getThreatIntelTriggerFromBytesReference(RemoteMonitorTrigger remoteMonitorTrigger, NamedXContentRegistry namedXContentRegistry) throws IOException {
        StreamInput triggerSin = StreamInput.wrap(remoteMonitorTrigger.getTrigger().toBytesRef().bytes);
        return new ThreatIntelTrigger(triggerSin);
    }

    public static ThreatIntelInput getThreatIntelInputFromBytesReference(BytesReference bytes, NamedXContentRegistry namedXContentRegistry) throws IOException {
        StreamInput sin = StreamInput.wrap(bytes.toBytesRef().bytes);
        ThreatIntelInput threatIntelInput = new ThreatIntelInput(sin);
        return threatIntelInput;
    }

    public static ThreatIntelMonitorDto buildThreatIntelMonitorDto(String id, Monitor monitor, NamedXContentRegistry namedXContentRegistry) throws IOException {
        RemoteDocLevelMonitorInput remoteDocLevelMonitorInput = (RemoteDocLevelMonitorInput) monitor.getInputs().get(0);
        List<String> indices = remoteDocLevelMonitorInput.getDocLevelMonitorInput().getIndices();
        ThreatIntelInput threatIntelInput = getThreatIntelInputFromBytesReference(remoteDocLevelMonitorInput.getInput(), namedXContentRegistry);
        return new ThreatIntelMonitorDto(
                id,
                monitor.getName(),
                threatIntelInput.getPerIocTypeScanInputList().stream().map(it -> new PerIocTypeScanInputDto(it.getIocType(), it.getIndexToFieldsMap())).collect(Collectors.toList()),
                monitor.getSchedule(),
                monitor.getEnabled(),
                monitor.getUser(),
                buildThreatIntelTriggerDtos(monitor.getTriggers(), namedXContentRegistry)
        );
    }

    /**
     * Fetch ACTIVE or ACKNOWLEDGED state alerts for the triggre. Criteria is they should match the ioc value+type from findings
     */
    public static SearchSourceBuilder getSearchSourceBuilderForExistingAlertsQuery(ArrayList<IocFinding> findings, Trigger trigger) {
        BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery();
        queryBuilder.must(QueryBuilders.matchQuery(ThreatIntelAlert.TRIGGER_NAME_FIELD, trigger.getName()));
        BoolQueryBuilder iocQueryBuilder = QueryBuilders.boolQuery();
        for (IocFinding finding : findings) {
            BoolQueryBuilder innerQb = QueryBuilders.boolQuery();
            innerQb.must(QueryBuilders.matchQuery(ThreatIntelAlert.IOC_TYPE_FIELD, finding.getIocType()));
            innerQb.must(QueryBuilders.matchQuery(ThreatIntelAlert.IOC_VALUE_FIELD, finding.getIocValue()));
            iocQueryBuilder.should(innerQb);
        }
        queryBuilder.must(iocQueryBuilder);
        BoolQueryBuilder stateQueryBuilder = QueryBuilders.boolQuery();
        stateQueryBuilder.should(QueryBuilders.matchQuery(ThreatIntelAlert.STATE_FIELD, Alert.State.ACTIVE.toString()));
        stateQueryBuilder.should(QueryBuilders.matchQuery(ThreatIntelAlert.STATE_FIELD, Alert.State.ACKNOWLEDGED.toString()));
        queryBuilder.must(stateQueryBuilder);

        SearchSourceBuilder ssb = new SearchSourceBuilder();
        ssb.query(queryBuilder);
        ssb.size(9999);
        return ssb;
    }


    public static Map<String, ThreatIntelAlert> prepareAlertsToUpdate(ArrayList<IocFinding> triggerMatchedFindings,
                                                                      List<ThreatIntelAlert> existingAlerts) {
        Map<String, ThreatIntelAlert> updatedAlerts = new HashMap<>();
        for (ThreatIntelAlert existingAlert : existingAlerts) {
            String iocType = existingAlert.getIocType();
            String iocValue = existingAlert.getIocValue();
            if (iocType == null || iocValue == null)
                continue;
            for (IocFinding finding : triggerMatchedFindings) {
                if (iocType.equals(finding.getIocType()) && iocValue.equals(finding.getIocValue())) {
                    List<String> findingIds = new ArrayList<>(existingAlert.getFindingIds());
                    findingIds.add(finding.getId());
                    updatedAlerts.put(existingAlert.getIocValue() + existingAlert.getIocType(), new ThreatIntelAlert(existingAlert, findingIds));
                }
            }
        }
        return updatedAlerts;

    }

    public static List<ThreatIntelAlert> prepareNewAlerts(Monitor monitor,
                                                          Trigger trigger,
                                                          ArrayList<IocFinding> findings,
                                                          Map<String, ThreatIntelAlert> updatedAlerts) {
        List<ThreatIntelAlert> alerts = new ArrayList<>();
        for (IocFinding finding : findings) {
            if (updatedAlerts.containsKey(finding.getIocValue() + finding.getIocType()))
                continue;
            Instant now = Instant.now();
            alerts.add(new ThreatIntelAlert(
                    UUID.randomUUID().toString(),
                    ThreatIntelAlert.NO_VERSION,
                    ThreatIntelAlert.NO_SCHEMA_VERSION,
                    monitor.getUser(),
                    trigger.getId(),
                    trigger.getName(),
                    monitor.getId(),
                    monitor.getName(),
                    Alert.State.ACTIVE,
                    now,
                    null,
                    now,
                    null,
                    null,
                    trigger.getSeverity(),
                    finding.getIocValue(),
                    finding.getIocType(),
                    Collections.emptyList(),
                    List.of(finding.getId())
            ));
        }
        return alerts;
    }

    public static ArrayList<IocFinding> getTriggerMatchedFindings(List<IocFinding> iocFindings, ThreatIntelTrigger threatIntelTrigger) {
        ArrayList<IocFinding> triggerMatchedFindings = new ArrayList();
        for (IocFinding iocFinding : iocFindings) {
            boolean iocTypeConditionMatch = false;
            if (threatIntelTrigger.getIocTypes() == null || threatIntelTrigger.getIocTypes().isEmpty()) {
                iocTypeConditionMatch = true;
            } else if (threatIntelTrigger.getIocTypes().contains(iocFinding.getIocType().toLowerCase())) {
                iocTypeConditionMatch = true;
            }
            boolean dataSourcesConditionMatch = false;
            if (threatIntelTrigger.getDataSources() == null || threatIntelTrigger.getDataSources().isEmpty()) {
                dataSourcesConditionMatch = true;
            } else {
                List<String> dataSources = iocFinding.getRelatedDocIds().stream().map(it -> {
                    String[] parts = it.split(":");
                    if (parts.length == 2) {
                        return parts[1];
                    } else return null;
                }).filter(Objects::nonNull).collect(Collectors.toList());
                if (threatIntelTrigger.getDataSources().stream().anyMatch(dataSources::contains)) {
                    dataSourcesConditionMatch = true;
                }
            }
            if (dataSourcesConditionMatch && iocTypeConditionMatch) {
                triggerMatchedFindings.add(iocFinding);
            }
        }
        return triggerMatchedFindings;
    }
}
