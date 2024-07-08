package org.opensearch.securityanalytics.threatIntel.sacommons.monitor;

import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.securityanalytics.model.threatintel.BaseEntity;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.util.XContentUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;
import static org.opensearch.securityanalytics.util.XContentUtils.getInstant;

public class ThreatIntelAlertDto extends BaseEntity {

    public static final String ALERT_ID_FIELD = "id";
    public static final String SCHEMA_VERSION_FIELD = "schema_version";
    public static final String SEQ_NO_FIELD = "seq_no";
    public static final String PRIMARY_TERM_FIELD = "primary_term";
    public static final String ALERT_VERSION_FIELD = "version";
    public static final String USER_FIELD = "user";
    public static final String TRIGGER_NAME_FIELD = "trigger_id";
    public static final String TRIGGER_ID_FIELD = "trigger_name";
    public static final String STATE_FIELD = "state";
    public static final String START_TIME_FIELD = "start_time";
    public static final String END_TIME_FIELD = "end_time";
    public static final String LAST_UPDATED_TIME_FIELD = "last_updated_time";
    public static final String ACKNOWLEDGED_TIME_FIELD = "acknowledged_time";
    public static final String ERROR_MESSAGE_FIELD = "error_message";
    public static final String SEVERITY_FIELD = "severity";
    public static final String ACTION_EXECUTION_RESULTS_FIELD = "action_execution_results";
    public static final String IOC_VALUE_FIELD = "ioc_value";
    public static final String IOC_TYPE_FIELD = "ioc_type";
    public static final String FINDING_IDS_FIELD = "finding_ids";
    public static final String NO_ID = "";
    public static final long NO_VERSION = 1L;
    public static final long NO_SCHEMA_VERSION = 0;

    private final String id;
    private final long version;
    private final long schemaVersion;
    private final long seqNo;
    private final long primaryTerm;
    private final User user;
    private final String triggerName;
    private final String triggerId;
    private final Alert.State state;
    private final Instant startTime;
    private final Instant endTime;
    private final Instant acknowledgedTime;
    private final Instant lastUpdatedTime;
    private final String errorMessage;
    private final String severity;
    private final String iocValue;
    private final String iocType;
    private List<String> findingIds;

    public ThreatIntelAlertDto(
            String id,
            long version,
            long schemaVersion,
            long seqNo,
            long primaryTerm,
            User user,
            String triggerId,
            String triggerName,
            Alert.State state,
            Instant startTime,
            Instant endTime,
            Instant lastUpdatedTime,
            Instant acknowledgedTime,
            String errorMessage,
            String severity,
            String iocValue,
            String iocType,
            List<String> findingIds
    ) {

        this.id = id != null ? id : NO_ID;
        this.version = version != 0 ? version : NO_VERSION;
        this.schemaVersion = schemaVersion;
        this.seqNo = seqNo;
        this.primaryTerm = primaryTerm;
        this.user = user;
        this.triggerId = triggerId;
        this.triggerName = triggerName;
        this.state = state;
        this.startTime = startTime;
        this.endTime = endTime;
        this.acknowledgedTime = acknowledgedTime;
        this.errorMessage = errorMessage;
        this.severity = severity;
        this.iocValue = iocValue;
        this.iocType = iocType;
        this.lastUpdatedTime = lastUpdatedTime;
        this.findingIds = findingIds;
    }

    public ThreatIntelAlertDto(StreamInput sin) throws IOException {
        this.id = sin.readString();
        this.version = sin.readLong();
        this.schemaVersion = sin.readLong();
        this.seqNo = sin.readLong();
        this.primaryTerm = sin.readLong();
        this.user = sin.readBoolean() ? new User(sin) : null;
        this.triggerId = sin.readString();
        this.triggerName = sin.readString();
        this.state = sin.readEnum(Alert.State.class);
        this.startTime = sin.readInstant();
        this.endTime = sin.readOptionalInstant();
        this.acknowledgedTime = sin.readOptionalInstant();
        this.errorMessage = sin.readOptionalString();
        this.severity = sin.readString();
        this.lastUpdatedTime = sin.readOptionalInstant();
        this.iocType = sin.readString();
        this.iocValue = sin.readString();
        this.findingIds = sin.readStringList();
    }

    public ThreatIntelAlertDto(ThreatIntelAlert alert, long seqNo, long primaryTerm) {
        this.id = alert.getId();
        this.version = alert.getVersion();
        this.schemaVersion = alert.getSchemaVersion();
        this.user = alert.getUser();
        this.triggerId = alert.getTriggerId();
        this.triggerName = alert.getTriggerName();
        this.state = alert.getState();
        this.startTime = alert.getStartTime();
        this.endTime = alert.getEndTime();
        this.acknowledgedTime = alert.getAcknowledgedTime();
        this.errorMessage = alert.getErrorMessage();
        this.severity = alert.getSeverity();
        this.iocValue = alert.getIocValue();
        this.iocType = alert.getIocType();
        this.lastUpdatedTime = alert.getLastUpdatedTime();
        this.findingIds = alert.getFindingIds();
        this.seqNo = seqNo;
        this.primaryTerm = primaryTerm;
    }

    public boolean isAcknowledged() {
        return state == Alert.State.ACKNOWLEDGED;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeLong(schemaVersion);
        out.writeLong(seqNo);
        out.writeLong(primaryTerm);
        out.writeBoolean(user != null);
        if (user != null) {
            user.writeTo(out);
        }
        out.writeString(triggerId);
        out.writeString(triggerName);
        out.writeEnum(state);
        out.writeInstant(startTime);
        out.writeOptionalInstant(endTime);
        out.writeOptionalInstant(acknowledgedTime);
        out.writeOptionalString(errorMessage);
        out.writeString(severity);
        out.writeOptionalInstant(lastUpdatedTime);
        out.writeString(iocType);
        out.writeString(iocValue);
        out.writeStringCollection(findingIds);
    }

    public static ThreatIntelAlertDto parse(XContentParser xcp, long version) throws IOException {
        String id = NO_ID;
        long schemaVersion = NO_SCHEMA_VERSION;
        long seqNo = SequenceNumbers.UNASSIGNED_SEQ_NO;
        long primaryTerm = SequenceNumbers.UNASSIGNED_PRIMARY_TERM;
        User user = null;
        String triggerId = null;
        String triggerName = null;
        Alert.State state = null;
        Instant startTime = null;
        String severity = null;
        Instant endTime = null;
        Instant acknowledgedTime = null;
        Instant lastUpdatedTime = null;
        String errorMessage = null;
        String iocValue = null;
        String iocType = null;
        List<String> findingIds = new ArrayList<>();

        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case USER_FIELD:
                    user = xcp.currentToken() == XContentParser.Token.VALUE_NULL ? null : User.parse(xcp);
                    break;
                case ALERT_ID_FIELD:
                    id = xcp.text();
                    break;
                case IOC_VALUE_FIELD:
                    iocValue = xcp.textOrNull();
                    break;
                case IOC_TYPE_FIELD:
                    iocType = xcp.textOrNull();
                    break;
                case ALERT_VERSION_FIELD:
                    version = xcp.longValue();
                    break;
                case SCHEMA_VERSION_FIELD:
                    schemaVersion = xcp.intValue();
                    break;
                case SEQ_NO_FIELD:
                    seqNo = xcp.longValue();
                    break;
                case PRIMARY_TERM_FIELD:
                    primaryTerm = xcp.longValue();
                    break;
                case TRIGGER_ID_FIELD:
                    triggerId = xcp.text();
                    break;
                case TRIGGER_NAME_FIELD:
                    triggerName = xcp.text();
                    break;
                case STATE_FIELD:
                    state = Alert.State.valueOf(xcp.text());
                    break;
                case ERROR_MESSAGE_FIELD:
                    errorMessage = xcp.textOrNull();
                    break;
                case SEVERITY_FIELD:
                    severity = xcp.text();
                    break;
                case START_TIME_FIELD:
                    startTime = getInstant(xcp);
                    break;
                case END_TIME_FIELD:
                    endTime = getInstant(xcp);
                    break;
                case ACKNOWLEDGED_TIME_FIELD:
                    acknowledgedTime = getInstant(xcp);
                    break;
                case LAST_UPDATED_TIME_FIELD:
                    lastUpdatedTime = getInstant(xcp);
                    break;
                case FINDING_IDS_FIELD:
                    ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        findingIds.add(xcp.text());
                    }
                default:
                    xcp.skipChildren();
            }
        }

        return new ThreatIntelAlertDto(id,
                version,
                schemaVersion,
                seqNo,
                primaryTerm,
                user,
                triggerId,
                triggerName,
                state,
                startTime,
                endTime,
                acknowledgedTime,
                lastUpdatedTime,
                errorMessage,
                severity,
                iocValue,
                iocType,
                findingIds);
    }

    public static Alert readFrom(StreamInput sin) throws IOException {
        return new Alert(sin);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return createXContentBuilder(builder, true);
    }

    @Override
    public String getId() {
        return id;
    }

    public XContentBuilder toXContentWithUser(XContentBuilder builder) throws IOException {
        return createXContentBuilder(builder, false);
    }

    private XContentBuilder createXContentBuilder(XContentBuilder builder, boolean secure) throws IOException {
        builder.startObject()
                .field(ALERT_ID_FIELD, id)
                .field(ALERT_VERSION_FIELD, version)
                .field(SCHEMA_VERSION_FIELD, schemaVersion)
                .field(SEQ_NO_FIELD, seqNo)
                .field(PRIMARY_TERM_FIELD, primaryTerm)
                .field(TRIGGER_NAME_FIELD, triggerName)
                .field(TRIGGER_ID_FIELD, triggerName)
                .field(STATE_FIELD, state)
                .field(ERROR_MESSAGE_FIELD, errorMessage)
                .field(IOC_VALUE_FIELD, iocValue)
                .field(IOC_TYPE_FIELD, iocType)
                .field(SEVERITY_FIELD, severity)
                .field(FINDING_IDS_FIELD, findingIds.toArray(new String[0]));
        XContentUtils.buildInstantAsField(builder, acknowledgedTime, ACKNOWLEDGED_TIME_FIELD);
        XContentUtils.buildInstantAsField(builder, lastUpdatedTime, LAST_UPDATED_TIME_FIELD);
        XContentUtils.buildInstantAsField(builder, startTime, START_TIME_FIELD);
        XContentUtils.buildInstantAsField(builder, endTime, END_TIME_FIELD);
        if (!secure) {
            if (user == null) {
                builder.nullField(USER_FIELD);
            } else {
                builder.field(USER_FIELD, user);
            }
        }
        return builder.endObject();
    }

    public Map<String, Object> asTemplateArg() {
        Map<String, Object> map = new HashMap<>();
        map.put(ACKNOWLEDGED_TIME_FIELD, acknowledgedTime != null ? acknowledgedTime.toEpochMilli() : null);
        map.put(ALERT_ID_FIELD, id);
        map.put(ALERT_VERSION_FIELD, version);
        map.put(END_TIME_FIELD, endTime != null ? endTime.toEpochMilli() : null);
        map.put(ERROR_MESSAGE_FIELD, errorMessage);
        map.put(SEVERITY_FIELD, severity);
        map.put(START_TIME_FIELD, startTime.toEpochMilli());
        map.put(STATE_FIELD, state.toString());
        map.put(TRIGGER_ID_FIELD, triggerId);
        map.put(TRIGGER_NAME_FIELD, triggerName);
        map.put(FINDING_IDS_FIELD, findingIds);
        map.put(LAST_UPDATED_TIME_FIELD, lastUpdatedTime);
        map.put(IOC_TYPE_FIELD, iocType);
        map.put(IOC_VALUE_FIELD, iocValue);
        return map;
    }

    public long getVersion() {
        return version;
    }

    public long getSchemaVersion() {
        return schemaVersion;
    }

    public User getUser() {
        return user;
    }

    public String getTriggerName() {
        return triggerName;
    }

    public Alert.State getState() {
        return state;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public Instant getAcknowledgedTime() {
        return acknowledgedTime;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public String getSeverity() {
        return severity;
    }

    public String getTriggerId() {
        return triggerId;
    }

    public Instant getLastUpdatedTime() {
        return lastUpdatedTime;
    }

    public String getIocValue() {
        return iocValue;
    }

    public String getIocType() {
        return iocType;
    }

    public List<String> getFindingIds() {
        return findingIds;
    }

    public long getSeqNo() {
        return seqNo;
    }

    public long getPrimaryTerm() {
        return primaryTerm;
    }
}