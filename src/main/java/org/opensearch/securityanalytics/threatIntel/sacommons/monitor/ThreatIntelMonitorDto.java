package org.opensearch.securityanalytics.threatIntel.sacommons.monitor;

import org.apache.commons.lang3.StringUtils;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Schedule;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.PerIocTypeScanInputDto;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class ThreatIntelMonitorDto implements Writeable, ToXContentObject, ThreatIntelMonitorDtoInterface {

    private static final String ID = "id";
    public static final String PER_IOC_TYPE_SCAN_INPUT_FIELD = "per_ioc_type_scan_input_list";
    public static final String INDICES = "indices";
    private final String id;
    private final String name;
    private final List<PerIocTypeScanInputDto> perIocTypeScanInputList;
    private final Schedule schedule;
    private final boolean enabled;
    private final User user;
    private final List<String> indices;

    public ThreatIntelMonitorDto(String id, String name, List<PerIocTypeScanInputDto> perIocTypeScanInputList, Schedule schedule, boolean enabled, User user, List<String> indices) {
        this.id = StringUtils.isBlank(id) ? UUID.randomUUID().toString() : id;
        this.name = name;
        this.perIocTypeScanInputList = perIocTypeScanInputList;
        this.schedule = schedule;
        this.enabled = enabled;
        this.user = user;
        this.indices = indices;
    }

    public ThreatIntelMonitorDto(StreamInput sin) throws IOException {
        this(
                sin.readOptionalString(),
                sin.readString(),
                sin.readList(PerIocTypeScanInputDto::new),
                Schedule.readFrom(sin),
                sin.readBoolean(),
                sin.readBoolean() ? new User(sin) : null,
                sin.readStringList());
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
        List<String> indices = new ArrayList<>();

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
                case Monitor.SCHEDULE_FIELD:
                    schedule = Schedule.parse(xcp);
                    break;
                case Monitor.ENABLED_FIELD:
                    enabled = xcp.booleanValue();
                    break;
                case Monitor.USER_FIELD:
                    user = xcp.currentToken() == XContentParser.Token.VALUE_NULL ? null : User.parse(xcp);
                    break;

                case INDICES:
                    List<String> strings = new ArrayList<>();
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        strings.add(xcp.text());
                    }
                    indices.addAll(strings);
                    break;
                default:
                    xcp.skipChildren();
                    break;
            }
        }

        return new ThreatIntelMonitorDto(id, name, inputs, schedule, enabled != null ? enabled : false, user, indices);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(id);
        out.writeString(name);
        out.writeList(perIocTypeScanInputList);
        schedule.writeTo(out);
        out.writeBoolean(enabled);
        user.writeTo(out);
        out.writeStringCollection(indices);
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
}
