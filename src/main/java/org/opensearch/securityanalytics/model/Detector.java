/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.function.Function;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.ParseField;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.commons.alerting.action.IndexMonitorRequest;
import org.opensearch.commons.alerting.model.CronSchedule;
import org.opensearch.commons.alerting.model.Schedule;
import org.opensearch.commons.authuser.User;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import java.util.stream.Collectors;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;

public class Detector implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(Detector.class);

    private static final String DETECTOR_TYPE = "detector";
    private static final String TYPE_FIELD = "type";
    public static final String DETECTOR_TYPE_FIELD = "detector_type";
    public static final String NAME_FIELD = "name";
    private static final String USER_FIELD = "user";
    public static final String ENABLED_FIELD = "enabled";
    public static final String SCHEDULE_FIELD = "schedule";
    public static final String NO_ID = "";
    public static final Long NO_VERSION = 1L;
    public static final String INPUTS_FIELD = "inputs";
    public static final String TRIGGERS_FIELD = "triggers";
    public static final String LAST_UPDATE_TIME_FIELD = "last_update_time";
    public static final String ENABLED_TIME_FIELD = "enabled_time";
    public static final String ALERTING_MONITOR_ID = "monitor_id";

    public static final String BUCKET_MONITOR_ID_RULE_ID = "bucket_monitor_id_rule_id";

    public static final String DOC_MONITOR_ID_PER_CATEGORY = "doc_monitor_id_per_category";
    private static final String RULE_TOPIC_INDEX = "rule_topic_index";

    private static final String ALERTS_INDEX = "alert_index";
    private static final String ALERTS_HISTORY_INDEX = "alert_history_index";
    private static final String ALERTS_HISTORY_INDEX_PATTERN = "alert_history_index_pattern";
    private static final String FINDINGS_INDEX = "findings_index";
    private static final String FINDINGS_INDEX_PATTERN = "findings_index_pattern";

    public static final String DETECTORS_INDEX = ".opensearch-sap-detectors-config";

    // Used as a key in rule-monitor map for the purpose of easy detection of the doc level monitor
    public static final String DOC_LEVEL_MONITOR = "-1";

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY = new NamedXContentRegistry.Entry(
            Detector.class,
            new ParseField(DETECTOR_TYPE),
            xcp -> parse(xcp, null, null)
    );


    private String id;

    private Long version;

    private String name;

    private Boolean enabled;

    private Schedule schedule;

    private Instant lastUpdateTime;

    private Instant enabledTime;

    private User user;

    private List<DetectorInput> inputs;

    private List<DetectorTrigger> triggers;

    private List<String> monitorIds;

    private Map<String, String> bucketRuleIdMonitorIdMap;

    private Map<String, String> docLevelMonitorPerCategory;

    private String ruleIndex;

    private String alertsIndex;

    private String alertsHistoryIndex;

    private String alertsHistoryIndexPattern;

    private String findingsIndex;

    private String findingsIndexPattern;

    private final String type;

    public Detector(String id, Long version, String name, Boolean enabled, Schedule schedule,
        Instant lastUpdateTime, Instant enabledTime,
        User user, List<DetectorInput> inputs, List<DetectorTrigger> triggers, List<String> monitorIds,
        String ruleIndex, String alertsIndex, String alertsHistoryIndex, String alertsHistoryIndexPattern,
        String findingsIndex, String findingsIndexPattern, Map<String, String> rulePerMonitor, Map<String, String> docLevelMonitorPerCategory) {
        this.type = DETECTOR_TYPE;

        this.id = id != null ? id : NO_ID;
        this.version = version != null ? version : NO_VERSION;
        this.name = name;
        this.enabled = enabled;
        this.schedule = schedule;
        this.lastUpdateTime = lastUpdateTime;
        this.enabledTime = enabledTime;
        this.user = user;
        this.inputs = inputs;
        this.triggers = triggers;
        this.monitorIds = monitorIds != null ? monitorIds : Collections.emptyList();
        this.ruleIndex = ruleIndex;
        this.alertsIndex = alertsIndex;
        this.alertsHistoryIndex = alertsHistoryIndex;
        this.alertsHistoryIndexPattern = alertsHistoryIndexPattern;
        this.findingsIndex = findingsIndex;
        this.findingsIndexPattern = findingsIndexPattern;
        this.bucketRuleIdMonitorIdMap = rulePerMonitor;
        this.docLevelMonitorPerCategory = docLevelMonitorPerCategory;

        if (enabled) {
            Objects.requireNonNull(enabledTime);
        }
    }

    public Detector(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(),
                sin.readString(),
                sin.readBoolean(),
                Schedule.readFrom(sin),
                sin.readInstant(),
                sin.readOptionalInstant(),
                sin.readBoolean() ? new User(sin) : null,
                sin.readList(DetectorInput::readFrom),
                sin.readList(DetectorTrigger::readFrom),
                sin.readStringList(),
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readMap(StreamInput::readString, StreamInput::readString),
                sin.readMap(StreamInput::readString, StreamInput::readString)
            );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeString(name);
        out.writeBoolean(enabled);
        if (schedule instanceof CronSchedule) {
            out.writeEnum(Schedule.TYPE.CRON);
        } else {
            out.writeEnum(Schedule.TYPE.INTERVAL);
        }
        schedule.writeTo(out);
        out.writeInstant(lastUpdateTime);
        out.writeOptionalInstant(enabledTime);
        out.writeBoolean(user != null);
        if (user != null) {
            user.writeTo(out);
        }
        out.writeVInt(inputs.size());
        for (DetectorInput it : inputs) {
            it.writeTo(out);
        }
        out.writeVInt(triggers.size());
        for (DetectorTrigger it: triggers) {
            it.writeTo(out);
        }
        out.writeStringCollection(monitorIds);
        out.writeString(ruleIndex);

        out.writeMap(bucketRuleIdMonitorIdMap, StreamOutput::writeString, StreamOutput::writeString);
        out.writeMap(docLevelMonitorPerCategory, StreamOutput::writeString, StreamOutput::writeString);
    }

    public XContentBuilder toXContentWithUser(XContentBuilder builder, Params params) throws IOException {
        return createXContentBuilder(builder, params, false);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return createXContentBuilder(builder, params, true);
    }

    public enum DetectorType {
        OTHERS_APPLICATION("others_application"),
        OTHERS_APT("others_apt"),
        OTHERS_CLOUD("others_cloud"),
        OTHERS_COMPLIANCE("others_compliance"),
        LINUX("linux"),
        OTHERS_MACOS("others_macos"),
        NETWORK("network"),
        OTHERS_PROXY("others_proxy"),
        OTHERS_WEB("others_web"),
        WINDOWS("windows"),
        AD_LDAP("ad_ldap"),
        APACHE_ACCESS("apache_access"),
        CLOUDTRAIL("cloudtrail"),
        DNS("dns"),
        S3("s3"),
        TEST_WINDOWS("test_windows");

        private String type;

        DetectorType(String type) {
            this.type = type;
        }

        public String getDetectorType() {
            return type;
        }

    }

    private XContentBuilder createXContentBuilder(XContentBuilder builder, ToXContent.Params params, Boolean secure) throws IOException {
        builder.startObject();
        if (params.paramAsBoolean("with_type", false)) {
            builder.startObject(type);
        }
        builder.field(TYPE_FIELD, type)
                .field(NAME_FIELD, name);

        if (!secure) {
            if (user == null) {
                builder.nullField(USER_FIELD);
            } else {
                builder.field(USER_FIELD, user);
            }
        }

        builder.field(ENABLED_FIELD, enabled);

        if (enabledTime == null) {
            builder.nullField(ENABLED_TIME_FIELD);
        } else {
            builder.timeField(ENABLED_TIME_FIELD, String.format(Locale.getDefault(), "%s_in_millis", ENABLED_TIME_FIELD), enabledTime.toEpochMilli());
        }

        builder.field(SCHEDULE_FIELD, schedule);

        DetectorInput[] inputsArray = new DetectorInput[]{};
        inputsArray = inputs.toArray(inputsArray);
        builder.field(INPUTS_FIELD, inputsArray);

        DetectorTrigger[] triggerArray = new DetectorTrigger[]{};
        triggerArray = triggers.toArray(triggerArray);
        builder.field(TRIGGERS_FIELD, triggerArray);

        if (lastUpdateTime == null) {
            builder.nullField(LAST_UPDATE_TIME_FIELD);
        } else {
            builder.timeField(LAST_UPDATE_TIME_FIELD, String.format(Locale.getDefault(), "%s_in_millis", LAST_UPDATE_TIME_FIELD), lastUpdateTime.toEpochMilli());
        }

        builder.field(ALERTING_MONITOR_ID, monitorIds);
        builder.field(BUCKET_MONITOR_ID_RULE_ID, bucketRuleIdMonitorIdMap);
        builder.field(DOC_MONITOR_ID_PER_CATEGORY, docLevelMonitorPerCategory);
        builder.field(RULE_TOPIC_INDEX, ruleIndex);
        builder.field(ALERTS_INDEX, alertsIndex);
        builder.field(ALERTS_HISTORY_INDEX, alertsHistoryIndex);
        builder.field(ALERTS_HISTORY_INDEX_PATTERN, alertsHistoryIndexPattern);
        builder.field(FINDINGS_INDEX, findingsIndex);
        builder.field(FINDINGS_INDEX_PATTERN, findingsIndexPattern);


        if (params.paramAsBoolean("with_type", false)) {
            builder.endObject();
        }
        return builder.endObject();
    }

    public static Detector docParse(XContentParser xcp, String id, Long version) throws IOException {
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        Detector detector = xcp.namedObject(Detector.class, xcp.currentName(), null);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, xcp.nextToken(), xcp);

        detector.setId(id);
        detector.setVersion(version);
        return detector;
    }

    public static Detector parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = NO_ID;
        }
        if (version == null) {
            version = NO_VERSION;
        }

        String name = null;
        String detectorType = null;
        User user = null;
        Schedule schedule = null;
        Instant lastUpdateTime = null;
        Instant enabledTime = null;
        Boolean enabled = true;
        List<DetectorInput> inputs = new ArrayList<>();
        List<DetectorTrigger> triggers = new ArrayList<>();
        List<String> monitorIds = new ArrayList<>();
        Map<String, String> rulePerMonitor = new HashMap<>();
        Map<String, String> docLevelRulePerCategory = new HashMap<>();

        String ruleIndex = null;
        String alertsIndex = null;
        String alertsHistoryIndex = null;
        String alertsHistoryIndexPattern = null;
        String findingsIndex = null;
        String findingsIndexPattern = null;

        List<String> allowedTypes = Arrays.stream(DetectorType.values()).map(DetectorType::getDetectorType).collect(Collectors.toList());

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case NAME_FIELD:
                    name = xcp.text();
                    break;
                case DETECTOR_TYPE_FIELD:
                    if (xcp.currentToken() != XContentParser.Token.VALUE_NULL) {
                        detectorType = xcp.text();
                        if (!allowedTypes.contains(detectorType.toLowerCase(Locale.ROOT))) {
                            throw new IllegalArgumentException(String.format(Locale.getDefault(),
                                "Detector type should be one of %s",
                                allowedTypes));
                        }
                        // In order to keep the existing detector types and to be backward compatible
                        if (detectorType != null && !inputs.get(0).getDetectorTypes().contains(DetectorType.valueOf(detectorType))) {
                            inputs.get(0).getDetectorTypes().add(DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)));
                        }
                        // Added on both places since not sure if there is an order in which fields are being parsed
                        // In order to be backward compatible - if there is doc_level_monitor key, that means that we had one detectorType supported
                        // Re-map from { 1 : docLevelMonitorId } to { rule_category: docLevelMonitorId }
                        if(rulePerMonitor.containsKey(DOC_LEVEL_MONITOR) && detectorType != null && !rulePerMonitor.containsKey(detectorType)) {
                            docLevelRulePerCategory.put(detectorType, rulePerMonitor.get(DOC_LEVEL_MONITOR));
                        }
                    }
                    break;
                case USER_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        user = null;
                    } else {
                        user = User.parse(xcp);
                    }
                    break;
                case ENABLED_FIELD:
                    enabled = xcp.booleanValue();
                    break;
                case SCHEDULE_FIELD:
                    schedule = Schedule.parse(xcp);
                    break;
                case INPUTS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        DetectorInput input = DetectorInput.parse(xcp);
                        inputs.add(input);
                    }
                    // In order to keep the existing detector types and to be backward compatible
                    if (detectorType != null && !inputs.get(0).getDetectorTypes().contains(DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)))) {
                        inputs.get(0).getDetectorTypes().add(DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)));
                    }
                    break;
                case TRIGGERS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        DetectorTrigger trigger = DetectorTrigger.parse(xcp);
                        triggers.add(trigger);
                    }
                    break;
                case ENABLED_TIME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        enabledTime = null;
                    } else if (xcp.currentToken().isValue()) {
                        enabledTime = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        enabledTime = null;
                    }
                    break;
                case LAST_UPDATE_TIME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        lastUpdateTime = null;
                    } else if (xcp.currentToken().isValue()) {
                        lastUpdateTime = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        lastUpdateTime = null;
                    }
                    break;
                case ALERTING_MONITOR_ID:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String monitorId = xcp.text();
                        monitorIds.add(monitorId);
                    }
                    break;
                case BUCKET_MONITOR_ID_RULE_ID:
                    rulePerMonitor = xcp.mapStrings();
                    // In order to be backward compatible - if there is doc_level_monitor key, that means that we had one detectorType supported
                    // Re-map from { 1 : docLevelMonitorId } to { rule_category: docLevelMonitorId }
                    if(rulePerMonitor.containsKey(DOC_LEVEL_MONITOR) && detectorType != null && !rulePerMonitor.containsKey(detectorType)) {
                       rulePerMonitor.put(detectorType, rulePerMonitor.get(DOC_LEVEL_MONITOR));
                    }

                    break;
                case DOC_MONITOR_ID_PER_CATEGORY:
                    docLevelRulePerCategory = xcp.mapStrings();

                    // In order to be backward compatible - if there is doc_level_monitor key, that means that we had one detectorType supported
                    // Re-map from { 1 : docLevelMonitorId } to { rule_category: docLevelMonitorId }
                    if(rulePerMonitor.containsKey(DOC_LEVEL_MONITOR) && detectorType != null && !rulePerMonitor.containsKey(detectorType)) {
                        docLevelRulePerCategory.put(detectorType, rulePerMonitor.get(DOC_LEVEL_MONITOR));
                    }
                    break;
                case RULE_TOPIC_INDEX:
                    ruleIndex = xcp.text();
                    break;
                case ALERTS_INDEX:
                    alertsIndex = xcp.text();
                    break;
                case ALERTS_HISTORY_INDEX:
                    alertsHistoryIndex = xcp.text();
                    break;
                case ALERTS_HISTORY_INDEX_PATTERN:
                    alertsHistoryIndexPattern = xcp.text();
                    break;
                case FINDINGS_INDEX:
                    findingsIndex = xcp.text();
                    break;
                case FINDINGS_INDEX_PATTERN:
                    findingsIndexPattern = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        if (enabled && enabledTime == null) {
            enabledTime = Instant.now();
        } else if (!enabled) {
            enabledTime = null;
        }

        return new Detector(
                id,
                version,
                Objects.requireNonNull(name, "Detector name is null"),
                enabled,
                Objects.requireNonNull(schedule, "Detector schedule is null"),
                lastUpdateTime != null ? lastUpdateTime : Instant.now(),
                enabledTime,
                user,
                inputs,
                triggers,
                monitorIds,
                ruleIndex,
                alertsIndex,
                alertsHistoryIndex,
                alertsHistoryIndexPattern,
                findingsIndex,
                findingsIndexPattern,
                rulePerMonitor,
                docLevelRulePerCategory
            );
    }

    public static Detector readFrom(StreamInput sin) throws IOException {
        return new Detector(sin);
    }

    public String getId() {
        return id;
    }

    public Long getVersion() {
        return version;
    }

    public String getName() {
        return name;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public Schedule getSchedule() {
        return schedule;
    }

    public Instant getLastUpdateTime() {
        return lastUpdateTime;
    }

    public Instant getEnabledTime() {
        return enabledTime;
    }

    public User getUser() {
        return user;
    }

    public List<DetectorInput> getInputs() {
        return inputs;
    }

    public List<DetectorTrigger> getTriggers() {
        return triggers;
    }

    public String getRuleIndex() {
        return ruleIndex;
    }

    public List<String> getDetectorTypes() {
        // In the case of detectors created before support of multiple detector types
        if(inputs == null || inputs.isEmpty() || inputs.get(0).getDetectorTypes().isEmpty()) {
            return Collections.emptyList();
        }
        return inputs.get(0).getDetectorTypes().stream().map(DetectorType::getDetectorType).collect(Collectors.toList());
    }

    public List<String> getRuleIndices() {
        return getDetectorTypes().stream().map(detectorType -> DetectorMonitorConfig.getRuleIndex(detectorType)).collect(
            Collectors.toList());
    }

    public List<String> getMonitorIds() {
        return monitorIds;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Map<String, String> getBucketRuleIdMonitorIdMap() {return bucketRuleIdMonitorIdMap; }

    public Map<String, String> getDocLevelMonitorPerCategory() {return docLevelMonitorPerCategory;}

    public String getDocLevelMonitorIdForRuleCategory (String ruleCategory) {
        return docLevelMonitorPerCategory.get(ruleCategory);
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    public void setEnabledTime(Instant enabledTime) {
        this.enabledTime = enabledTime;
    }

    public void setLastUpdateTime(Instant lastUpdateTime) {
        this.lastUpdateTime = lastUpdateTime;
    }

    public void setInputs(List<DetectorInput> inputs) {
        this.inputs = inputs;
    }

    public void setMonitorIds(List<String> monitorIds) {
        this.monitorIds = monitorIds;
    }
    public void setBucketRuleIdMonitorIdMap(Map<String, String> bucketRuleIdMonitorIdMap) {
        this.bucketRuleIdMonitorIdMap = bucketRuleIdMonitorIdMap;
    }

    public void setDocLevelMonitorPerCategory(Map<String, String> docLevelMonitorPerCategory) {
        this.docLevelMonitorPerCategory = docLevelMonitorPerCategory;
    }

    public List<String> getMonitorIdsToBeDeleted(List<IndexMonitorRequest> monitorsToBeUpdated) {
        List<String> monitorIdsToBeDeleted = bucketRuleIdMonitorIdMap.values().stream().collect(Collectors.toList());
        monitorIdsToBeDeleted.addAll(docLevelMonitorPerCategory.values().stream().collect(Collectors.toList()));

        List<String> monitorIds = monitorsToBeUpdated.stream().map(IndexMonitorRequest::getMonitorId).collect(
            Collectors.toList());
        monitorIdsToBeDeleted.removeAll(monitorIds);

        return monitorIdsToBeDeleted;
    }

    public List<String> getRuleTopicsForMonitors(List<String> monitorIds) {
        Set<String> monitorIdsSet = new HashSet<>(monitorIds);
        List<String> ruleTopics = new ArrayList<>();

        for (Entry<String, String> categoryDocMonitorId: docLevelMonitorPerCategory.entrySet()) {
            if (monitorIdsSet.contains(categoryDocMonitorId.getValue())) {
                String ruleCategory = categoryDocMonitorId.getKey();
                ruleTopics.add(DetectorMonitorConfig.getRuleIndex(ruleCategory));
            }
        }
        return ruleTopics;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Detector detector = (Detector) o;
        return Objects.equals(id, detector.id) && Objects.equals(version, detector.version) && Objects.equals(name, detector.name) && Objects.equals(enabled, detector.enabled) && Objects.equals(schedule, detector.schedule) && Objects.equals(lastUpdateTime, detector.lastUpdateTime) && Objects.equals(enabledTime, detector.enabledTime) && ((user == null && detector.user == null) || Objects.equals(user, detector.user)) && Objects.equals(inputs, detector.inputs) && Objects.equals(triggers, detector.triggers) && Objects.equals(type, detector.type) && Objects.equals(monitorIds, detector.monitorIds) && Objects.equals(ruleIndex, detector.ruleIndex);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, version, name, enabled, schedule, lastUpdateTime, enabledTime, user, inputs, triggers, type, monitorIds, ruleIndex);
    }
}
