package org.opensearch.securityanalytics.threatIntel.util;

import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Trigger;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteDocLevelMonitorInput;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteMonitorTrigger;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.PerIocTypeScanInputDto;
import org.opensearch.securityanalytics.threatIntel.model.monitor.ThreatIntelInput;
import org.opensearch.securityanalytics.threatIntel.model.monitor.ThreatIntelTrigger;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelTriggerDto;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.util.XContentUtils.getBytesReference;

public class ThreatIntelMonitorUtils    {
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

    public static ThreatIntelInput getThreatIntelInputFromBytesReference(BytesReference bytes) throws IOException {
        StreamInput sin = StreamInput.wrap(bytes.toBytesRef().bytes);
        ThreatIntelInput threatIntelInput = new ThreatIntelInput(sin);
        return threatIntelInput;
    }

    public static ThreatIntelMonitorDto buildThreatIntelMonitorDto(String id, Monitor monitor, NamedXContentRegistry namedXContentRegistry) throws IOException {
        RemoteDocLevelMonitorInput remoteDocLevelMonitorInput = (RemoteDocLevelMonitorInput) monitor.getInputs().get(0);
        List<String> indices = remoteDocLevelMonitorInput.getDocLevelMonitorInput().getIndices();
        ThreatIntelInput threatIntelInput = getThreatIntelInputFromBytesReference(remoteDocLevelMonitorInput.getInput());
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
}
