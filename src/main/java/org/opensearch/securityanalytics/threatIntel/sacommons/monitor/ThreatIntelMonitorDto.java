package org.opensearch.securityanalytics.threatIntel.sacommons.monitor;

import org.apache.commons.lang3.StringUtils;
import org.opensearch.commons.alerting.model.CronSchedule;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Schedule;
import org.opensearch.commons.alerting.model.ScheduledJob;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteDocLevelMonitorInput;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteMonitorInput;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.PerIocTypeScanInputDto;
import org.opensearch.securityanalytics.threatIntel.model.monitor.ThreatIntelInput;
import org.opensearch.securityanalytics.threatIntel.util.ThreatIntelMonitorUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class ThreatIntelMonitorDto implements Writeable, ToXContentObject, ThreatIntelMonitorDtoInterface {

    private static final String ID = "id";
    public static final String PER_IOC_TYPE_SCAN_INPUT_FIELD = "per_ioc_type_scan_input_list";
    public static final String INDICES = "indices";
    public static final String TRIGGERS_FIELD = "triggers";
    private final String id;
    private final String name;
    private final List<PerIocTypeScanInputDto> perIocTypeScanInputList;
    private final Schedule schedule;
    private final boolean enabled;
    private final User user;
    private final List<String> indices;
    private final List<ThreatIntelTriggerDto> triggers;

    public ThreatIntelMonitorDto(String id, String name, List<PerIocTypeScanInputDto> perIocTypeScanInputList, Schedule schedule, boolean enabled, User user, List<ThreatIntelTriggerDto> triggers) {
        this.id = StringUtils.isBlank(id) ? UUID.randomUUID().toString() : id;
        this.name = name;
        this.perIocTypeScanInputList = perIocTypeScanInputList;
        this.schedule = schedule;
        this.enabled = enabled;
        this.user = user;
        this.indices = getIndices(perIocTypeScanInputList);
        this.triggers = triggers;
    }

    private List<String> getIndices(List<PerIocTypeScanInputDto> perIocTypeScanInputList) {
        if (perIocTypeScanInputList == null)
            return Collections.emptyList();
        List<String> list = new ArrayList<>();
        Set<String> uniqueValues = new HashSet<>();
        for (PerIocTypeScanInputDto dto : perIocTypeScanInputList) {
            Map<String, List<String>> indexToFieldsMap = dto.getIndexToFieldsMap() == null ? Collections.emptyMap() : dto.getIndexToFieldsMap();
            for (String s : indexToFieldsMap.keySet()) {
                if (uniqueValues.add(s)) {
                    list.add(s);
                }
            }
        }
        return list;
    }

    public ThreatIntelMonitorDto(StreamInput sin) throws IOException {
        this(
                sin.readOptionalString(),
                sin.readString(),
                sin.readList(PerIocTypeScanInputDto::new),
                Schedule.readFrom(sin),
                sin.readBoolean(),
                sin.readBoolean() ? new User(sin) : null,
                sin.readList(ThreatIntelTriggerDto::new));
    }

    public static ThreatIntelMonitorDto readFrom(StreamInput sin) throws IOException {
        return new ThreatIntelMonitorDto(sin);
    }

    public static ThreatIntelMonitorDto parse(XContentParser xcp, String id, Long version) throws IOException {
        String name = null;
        List<PerIocTypeScanInputDto> inputs = new ArrayList<>();
        Schedule schedule = null;
        Boolean enabled = null;
        User user = null;
        List<ThreatIntelTriggerDto> triggers = new ArrayList<>();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case ID:
                    id = xcp.text();
                    break;
                case Monitor.NAME_FIELD:
                    name = xcp.text();
                    break;
                case PER_IOC_TYPE_SCAN_INPUT_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        PerIocTypeScanInputDto input = PerIocTypeScanInputDto.parse(xcp);
                        inputs.add(input);
                    }
                    break;
                case TRIGGERS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        ThreatIntelTriggerDto input = ThreatIntelTriggerDto.parse(xcp);
                        triggers.add(input);
                    }
                    break;
                case Monitor.SCHEDULE_FIELD:
                    schedule = Schedule.parse(xcp);
                    break;
                case Monitor.ENABLED_FIELD:
                    enabled = xcp.booleanValue();
                    break;
                case Monitor.USER_FIELD:
                    user = xcp.currentToken() == XContentParser.Token.VALUE_NULL ? null : User.parse(xcp);
                    break;
                default:
                    xcp.skipChildren();
                    break;
            }
        }

        return new ThreatIntelMonitorDto(id, name, inputs, schedule, enabled != null ? enabled : false, user, triggers);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(id);
        out.writeString(name);
        out.writeList(perIocTypeScanInputList);
        if (schedule instanceof CronSchedule) {
            out.writeEnum(Schedule.TYPE.CRON);
        } else {
            out.writeEnum(Schedule.TYPE.INTERVAL);
        }
        schedule.writeTo(out);
        out.writeBoolean(enabled);
        user.writeTo(out);
        out.writeStringCollection(indices);
        out.writeList(triggers);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(ID, id)
                .field(Monitor.NAME_FIELD, name)
                .field(PER_IOC_TYPE_SCAN_INPUT_FIELD, perIocTypeScanInputList)
                .field(Monitor.SCHEDULE_FIELD, schedule)
                .field(Monitor.ENABLED_FIELD, enabled)
                .field(Monitor.USER_FIELD, user)
                .field(INDICES, indices)
                .field(TRIGGERS_FIELD, triggers)
                .endObject();
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public List<PerIocTypeScanInputDto> getPerIocTypeScanInputList() {
        return perIocTypeScanInputList;
    }

    public Schedule getSchedule() {
        return schedule;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public User getUser() {
        return user;
    }

    public List<String> getIndices() {
        return indices;
    }

    public List<ThreatIntelTriggerDto> getTriggers() {
        return triggers;
    }
}
