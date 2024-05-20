/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.threatIntel.model;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.jobscheduler.spi.schedule.Schedule;
import org.opensearch.jobscheduler.spi.schedule.ScheduleParser;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.sacommons.TIFConfigDto;

import java.io.IOException;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;

public class SATIFConfigDto implements Writeable, ToXContentObject, TIFConfigDto{

    public static final String NO_ID = "";
    public static final String ID_FIELD = "id";

    public static final Long NO_VERSION = 1L;
    public static final String VERSION_FIELD = "version";
    public static final String FEED_NAME_FIELD = "feed_name";
    public static final String FEED_FORMAT_FIELD = "feed_format";
    public static final String PREPACKAGED_FIELD = "prepackaged";
    public static final String CREATED_BY_USER_FIELD = "created_by_user";
    public static final String CREATED_AT_FIELD = "created_at";
    public static final String SOURCE_FIELD = "source";
    public static final String ENABLED_TIME_FIELD = "enabled_time";
    public static final String LAST_UPDATE_TIME_FIELD = "last_update_time";
    public static final String SCHEDULE_FIELD = "schedule";
    public static final String STATE_FIELD = "state";
    public static final String REFRESH_TYPE_FIELD = "refresh_type";
    public static final String LAST_REFRESHED_TIME_FIELD = "last_refreshed_time";
    public static final String LAST_REFRESHED_USER_FIELD = "last_refreshed_user";
    public static final String ENABLED_FIELD = "enabled";
    public static final String IOC_MAP_STORE_FIELD = "ioc_map_store";

    private String id;
    private Long version;
    private String feedName;
    private String feedFormat;
    private Boolean prepackaged;
    private String createdByUser;
    private Instant createdAt;

    //    private Source source; TODO: create Source Object
    private Instant enabledTime;
    private Instant lastUpdateTime;
    private Schedule schedule;
    private TIFJobState state;
    public String refreshType;
    public Instant lastRefreshedTime;
    public String lastRefreshedUser;
    private Boolean isEnabled;
    private Map<String, Object> iocMapStore;

    public SATIFConfigDto(SATIFConfig satifConfig) {
        this.id = satifConfig.getId();
        this.version = satifConfig.getVersion();
        this.feedName = satifConfig.getName();
        this.feedFormat = satifConfig.getFeedFormat();
        this.prepackaged = satifConfig.getPrepackaged();
        this.createdByUser = satifConfig.getCreatedByUser();
        this.createdAt = satifConfig.getCreatedAt();
        this.enabledTime = satifConfig.getEnabledTime();
        this.lastUpdateTime = satifConfig.getLastUpdateTime();
        this.schedule = satifConfig.getSchedule();
        this.state = satifConfig.getState();;
        this.refreshType = satifConfig.getRefreshType();
        this.lastRefreshedTime = satifConfig.getLastRefreshedTime();
        this.lastRefreshedUser = satifConfig.getLastRefreshedUser();
        this.isEnabled = satifConfig.isEnabled();;
        this.iocMapStore = satifConfig.getIocMapStore();
    }

    public SATIFConfigDto(String id, Long version, String feedName, String feedFormatId, Boolean prepackaged, String createdByUser, Instant createdAt,
                       Instant enabledTime, Instant lastUpdateTime, Schedule schedule, TIFJobState state, String refreshType, Instant lastRefreshedTime, String lastRefreshedUser,
                       Boolean isEnabled, Map<String, Object> iocMapStore) {
        this.id = id != null ? id : NO_ID;
        this.version = version != null ? version : NO_VERSION;
        this.feedName = feedName;
        this.feedFormat = feedFormatId;
        this.prepackaged = prepackaged;
        this.createdByUser = createdByUser;
        this.createdAt = createdAt;
        this.enabledTime = enabledTime;
        this.lastUpdateTime = lastUpdateTime;
        this.schedule = schedule;
        this.state = state;
        this.refreshType = refreshType;
        this.lastRefreshedTime = lastRefreshedTime;
        this.lastRefreshedUser = lastRefreshedUser;
        this.isEnabled = isEnabled;
        this.iocMapStore = iocMapStore;
    }

    public SATIFConfigDto(StreamInput sin) throws IOException {
        this(new SATIFConfig(sin));
    }

    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeString(feedName);
        out.writeString(feedFormat);
        out.writeBoolean(prepackaged);
        out.writeString(createdByUser);
        out.writeInstant(createdAt);
        out.writeInstant(enabledTime);
        out.writeInstant(lastUpdateTime);
        schedule.writeTo(out);
        out.writeString(state.name());
        out.writeString(refreshType);
        out.writeOptionalInstant(lastRefreshedTime == null ? null : lastRefreshedTime);
        out.writeOptionalString(lastRefreshedUser == null? null : lastRefreshedUser);
        out.writeBoolean(isEnabled);
        out.writeMap(iocMapStore);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject();
        builder.field(ID_FIELD, id);
        builder.field(VERSION_FIELD, version);
        builder.field(FEED_NAME_FIELD, feedName);
        builder.field(FEED_FORMAT_FIELD, feedFormat);
        builder.field(PREPACKAGED_FIELD, prepackaged);
        builder.field(CREATED_BY_USER_FIELD, createdByUser);

        if (createdAt == null) {
            builder.nullField(CREATED_AT_FIELD);
        } else {
            builder.timeField(CREATED_AT_FIELD, String.format(Locale.getDefault(), "%s_in_millis", CREATED_AT_FIELD), createdAt.toEpochMilli());
        }

        if (enabledTime == null) {
            builder.nullField(ENABLED_TIME_FIELD);
        } else {
            builder.timeField(ENABLED_TIME_FIELD, String.format(Locale.getDefault(), "%s_in_millis", ENABLED_TIME_FIELD), enabledTime.toEpochMilli());
        }

        if (lastUpdateTime == null) {
            builder.nullField(LAST_UPDATE_TIME_FIELD);
        } else {
            builder.timeField(LAST_UPDATE_TIME_FIELD, String.format(Locale.getDefault(), "%s_in_millis", LAST_UPDATE_TIME_FIELD), lastUpdateTime.toEpochMilli());
        }

        builder.field(SCHEDULE_FIELD, schedule);
        builder.field(STATE_FIELD, state.name());
        builder.field(REFRESH_TYPE_FIELD, refreshType);
        if (lastRefreshedTime == null) {
            builder.nullField(LAST_REFRESHED_TIME_FIELD);
        } else {
            builder.timeField(LAST_REFRESHED_TIME_FIELD, String.format(Locale.getDefault(), "%s_in_millis",
                    LAST_REFRESHED_TIME_FIELD), lastRefreshedTime.toEpochMilli());
        }
        builder.field(LAST_REFRESHED_USER_FIELD, lastRefreshedUser);
        builder.field(ENABLED_FIELD, isEnabled);
        builder.field(IOC_MAP_STORE_FIELD, iocMapStore);
        builder.endObject();

        return builder;
    }

    public static SATIFConfigDto parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = NO_ID;
        }
        if (version == null) {
            version = NO_VERSION;
        }

        String feedName = null;
        String feedFormat = null;
        Boolean prepackaged = null;
        String createdByUser = null;
        Instant createdAt = null;
        Instant enabledTime = null;
        Instant lastUpdateTime = null;
        Schedule schedule = null;
        TIFJobState state = null;
        String refreshType = null;
        Instant lastRefreshedTime = null;
        String lastRefreshedUser = null;
        Boolean isEnabled = null;
        Map<String,Object> iocMapStore = null;

        xcp.nextToken();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case FEED_NAME_FIELD:
                    feedName = xcp.text();
                    break;
                case FEED_FORMAT_FIELD:
                    feedFormat = xcp.text();
                    break;
                case PREPACKAGED_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        prepackaged = null;
                    } else {
                        prepackaged = xcp.booleanValue();
                    }
                    break;
                case CREATED_BY_USER_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        createdByUser = null;
                    } else {
                        createdByUser = xcp.text();
                    }
                    break;
                case CREATED_AT_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        createdAt = null;
                    } else if (xcp.currentToken().isValue()) {
                        createdAt = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        createdAt = null;
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
                case SCHEDULE_FIELD:
                    schedule = ScheduleParser.parse(xcp);
                    break;
                case STATE_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        state = TIFJobState.CREATING;
                    } else {
                        state = toState(xcp.text());
                    }
                    break;
                case REFRESH_TYPE_FIELD:
                    refreshType = xcp.text();
                    break;
                case LAST_REFRESHED_TIME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        lastRefreshedTime = null;
                    } else if (xcp.currentToken().isValue()) {
                        lastRefreshedTime = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        lastRefreshedTime = null;
                    }
                    break;
                case LAST_REFRESHED_USER_FIELD:
                    lastRefreshedUser = xcp.text();
                case ENABLED_FIELD:
                    isEnabled = xcp.booleanValue();
                    break;
                case IOC_MAP_STORE_FIELD:
                    iocMapStore = xcp.map();
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        if (isEnabled && enabledTime == null) {
            createdAt = Instant.now();
            enabledTime = Instant.now();
        } else if (!isEnabled) {
            enabledTime = null;
        }


        return new SATIFConfigDto(
                id,
                version,
                feedName,
                feedFormat,
                prepackaged,
                createdByUser,
                createdAt != null ? createdAt : Instant.now(),
                enabledTime,
                lastUpdateTime != null ? lastUpdateTime : Instant.now(),
                schedule,
                state,
                refreshType,
                lastRefreshedTime,
                lastRefreshedUser,
                isEnabled,
                iocMapStore
        );
    }

    // TODO: refactor out to sa commons
    public static TIFJobState toState(String stateName) {
        if (stateName.equals("CREATING")) {
            return TIFJobState.CREATING;
        }
        if (stateName.equals("AVAILABLE")) {
            return TIFJobState.AVAILABLE;
        }
        if (stateName.equals("CREATE_FAILED")) {
            return TIFJobState.CREATE_FAILED;
        }
        if (stateName.equals("DELETING")) {
            return TIFJobState.DELETING;
        }
        if (stateName.equals("REFRESH_FAILED")) {
            return TIFJobState.REFRESH_FAILED;
        }
        return null;
    }


    // Getters and Setters
    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }
    public Long getVersion() {
        return version;
    }
    public void setVersion(Long version) {
        this.version = version;
    }
    public String getName() {
        return this.feedName;
    }
    public void setName(String name) {
        this.feedName = name;
    }
    public String getFeedFormat() {
        return feedFormat;
    }
    public void setFeedFormat(String feedFormat) {
        this.feedFormat = feedFormat;
    }
    public Boolean getPrepackaged() {
        return prepackaged;
    }
    public void setPrepackaged(Boolean prepackaged) {
        this.prepackaged = prepackaged;
    }
    public String getCreatedByUser() {
        return createdByUser;
    }
    public void setCreatedByUser(String createdByUser) {
        this.createdByUser = createdByUser;
    }
    public Instant getCreatedAt() {
        return createdAt;
    }
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
    public Instant getEnabledTime() {
        return this.enabledTime;
    }
    public void setEnabledTime(Instant enabledTime) {
        this.enabledTime = enabledTime;
    }
    public Instant getLastUpdateTime() {
        return this.lastUpdateTime;
    }
    public void setLastUpdateTime(Instant lastUpdateTime) {
        this.lastUpdateTime = lastUpdateTime;
    }
    public Schedule getSchedule() {
        return this.schedule;
    }
    public void setSchedule(Schedule schedule) {
        this.schedule = schedule;
    }
    public TIFJobState getState() {
        return state;
    }
    public void setState(TIFJobState previousState) {
        this.state = previousState;
    }
    public String getLastRefreshedUser() {
        return lastRefreshedUser;
    }
    public void setLastRefreshedUser(String lastRefreshedUser) {
        this.lastRefreshedUser = lastRefreshedUser;
    }
    public Instant getLastRefreshedTime() {
        return lastRefreshedTime;
    }
    public void setLastRefreshedTime(Instant lastRefreshedTime) {
        this.lastRefreshedTime = lastRefreshedTime;
    }
    public String getRefreshType() {
        return refreshType;
    }
    public void setRefreshType(String refreshType) {
        this.refreshType = refreshType;
    }
    public boolean isEnabled() {
        return this.isEnabled;
    }

    /**
     * Enable auto update of threat intel feed data
     */
    public void enable() {
        if (isEnabled == true) {
            return;
        }
        enabledTime = Instant.now();
        isEnabled = true;
    }

    /**
     * Disable auto update of threat intel feed data
     */
    public void disable() {
        enabledTime = null;
        isEnabled = false;
    }
    public Map<String, Object> getIocMapStore() {
        return iocMapStore;
    }
    public void setIocMapStore(Map<String, Object> iocMapStore) {
        this.iocMapStore = iocMapStore;
    }
    public static SATIFConfigDto readFrom(StreamInput sin) throws IOException {
        return new SATIFConfigDto(sin);
    }
}