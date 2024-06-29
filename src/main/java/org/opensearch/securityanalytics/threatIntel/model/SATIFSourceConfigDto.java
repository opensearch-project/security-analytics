/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.threatIntel.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.UUIDs;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.jobscheduler.spi.schedule.Schedule;
import org.opensearch.jobscheduler.spi.schedule.ScheduleParser;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.common.RefreshType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.sacommons.TIFSourceConfigDto;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Implementation of TIF Config Dto to store the source configuration metadata as DTO object
 */
public class SATIFSourceConfigDto implements Writeable, ToXContentObject, TIFSourceConfigDto {

    private static final Logger log = LogManager.getLogger(SATIFSourceConfigDto.class);

    public static final String SOURCE_CONFIG_FIELD = "source_config";

    public static final String NO_ID = "";

    public static final Long NO_VERSION = 1L;
    public static final String VERSION_FIELD = "version";

    public static final String NAME_FIELD = "name";
    public static final String FORMAT_FIELD = "format";
    public static final String TYPE_FIELD = "type";

    public static final String DESCRIPTION_FIELD = "description";
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
    public static final String IOC_TYPES_FIELD = "ioc_types";

    private String id;
    private Long version;
    private String name;
    private String format;
    private SourceConfigType type;
    private String description;
    private User createdByUser;
    private Instant createdAt;
    private Source source;
    private Instant enabledTime;
    private Instant lastUpdateTime;
    private Schedule schedule;
    private TIFJobState state;
    public RefreshType refreshType;
    public Instant lastRefreshedTime;
    public User lastRefreshedUser;
    private Boolean isEnabled;
    private List<String> iocTypes;

    public SATIFSourceConfigDto(SATIFSourceConfig saTifSourceConfig) {
        this.id = saTifSourceConfig.getId();
        this.version = saTifSourceConfig.getVersion();
        this.name = saTifSourceConfig.getName();
        this.format = saTifSourceConfig.getFormat();
        this.type = saTifSourceConfig.getType();
        this.description = saTifSourceConfig.getDescription();
        this.createdByUser = saTifSourceConfig.getCreatedByUser();
        this.createdAt = saTifSourceConfig.getCreatedAt();
        this.source = saTifSourceConfig.getSource();
        this.enabledTime = saTifSourceConfig.getEnabledTime();
        this.lastUpdateTime = saTifSourceConfig.getLastUpdateTime();
        this.schedule = saTifSourceConfig.getSchedule();
        this.state = saTifSourceConfig.getState();
        this.refreshType = saTifSourceConfig.getRefreshType();
        this.lastRefreshedTime = saTifSourceConfig.getLastRefreshedTime();
        this.lastRefreshedUser = saTifSourceConfig.getLastRefreshedUser();
        this.isEnabled = saTifSourceConfig.isEnabled();
        this.iocTypes = saTifSourceConfig.getIocTypes();
    }

    private List<STIX2IOCDto> convertToIocDtos(List<STIX2IOC> stix2IocList) {
        return stix2IocList.stream()
                .map(STIX2IOCDto::new)
                .collect(Collectors.toList());
    }
    public SATIFSourceConfigDto(String id, Long version, String name, String format, SourceConfigType type, String description, User createdByUser, Instant createdAt, Source source,
                                Instant enabledTime, Instant lastUpdateTime, Schedule schedule, TIFJobState state, RefreshType refreshType, Instant lastRefreshedTime, User lastRefreshedUser,
                                Boolean isEnabled, List<String> iocTypes) {
        this.id = id == null ? UUIDs.base64UUID() : id;
        this.version = version != null ? version : NO_VERSION;
        this.name = name;
        this.format = format;
        this.type = type;
        this.description = description;
        this.createdByUser = createdByUser;
        this.source = source;
        this.createdAt = createdAt != null ? createdAt : Instant.now();

        if (isEnabled && enabledTime == null) {
            this.enabledTime = Instant.now();
        } else if (!isEnabled) {
            this.enabledTime = null;
        } else {
            this.enabledTime = enabledTime;
        }

        this.lastUpdateTime = lastUpdateTime != null ? lastUpdateTime : Instant.now();
        this.schedule = schedule;
        this.state = state != null ? state : TIFJobState.CREATING;
        this.refreshType = refreshType != null ? refreshType : RefreshType.FULL;
        this.lastRefreshedTime = lastRefreshedTime;
        this.lastRefreshedUser = lastRefreshedUser;
        this.isEnabled = isEnabled;
        this.iocTypes = iocTypes;
    }

    public SATIFSourceConfigDto(StreamInput sin) throws IOException {
        this(
                sin.readString(), // id
                sin.readLong(), // version
                sin.readString(), // name
                sin.readString(), // format
                SourceConfigType.valueOf(sin.readString()), // type
                sin.readOptionalString(), // description
                sin.readBoolean()? new User(sin) : null, // created by user
                sin.readInstant(), // created at
                sin.readBoolean()? Source.readFrom(sin) : null, // source
                sin.readOptionalInstant(), // enabled time
                sin.readInstant(), // last update time
                sin.readBoolean()? new IntervalSchedule(sin) : null, // schedule
                TIFJobState.valueOf(sin.readString()), // state
                RefreshType.valueOf(sin.readString()), // refresh type
                sin.readOptionalInstant(), // last refreshed time
                sin.readBoolean()? new User(sin) : null, // last refreshed user
                sin.readBoolean(), // is enabled
                sin.readStringList() // ioc types
        );
    }

    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeString(name);
        out.writeString(format);
        out.writeString(type.name());
        out.writeOptionalString(description);
        out.writeBoolean(createdByUser != null);
        if (createdByUser != null) {
            createdByUser.writeTo(out);
        }
        out.writeInstant(createdAt);
        if (source != null ) {
            if (source instanceof S3Source) {
                out.writeEnum(Source.Type.S3);
            } else if (source instanceof IocUploadSource) {
                out.writeEnum(Source.Type.IOC_UPLOAD);
            }
        }
        source.writeTo(out);
        out.writeOptionalInstant(enabledTime);
        out.writeInstant(lastUpdateTime);
        out.writeBoolean(schedule != null);
        if (schedule != null) {
            schedule.writeTo(out);
        }
        out.writeString(state.name());
        out.writeString(refreshType.name());
        out.writeOptionalInstant(lastRefreshedTime);
        out.writeBoolean(lastRefreshedUser != null);
        if (lastRefreshedUser != null) {
            lastRefreshedUser.writeTo(out);
        }
        out.writeBoolean(isEnabled);
        out.writeStringCollection(iocTypes);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject()
                .startObject(SOURCE_CONFIG_FIELD)
                .field(NAME_FIELD, name)
                .field(FORMAT_FIELD, format)
                .field(TYPE_FIELD, type.name())
                .field(DESCRIPTION_FIELD, description);
        if (createdByUser == null) {
            builder.nullField(CREATED_BY_USER_FIELD);
        } else {
            builder.field(CREATED_BY_USER_FIELD, createdByUser);
        }

        if (source == null) {
            builder.nullField(SOURCE_FIELD);
        } else {
            builder.field(SOURCE_FIELD, source);
        }

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

        if (schedule == null) {
            builder.nullField(SCHEDULE_FIELD);
        } else {
            builder.field(SCHEDULE_FIELD, schedule);
        }

        builder.field(STATE_FIELD, state.name());
        builder.field(REFRESH_TYPE_FIELD, refreshType.name());
        if (lastRefreshedTime == null) {
            builder.nullField(LAST_REFRESHED_TIME_FIELD);
        } else {
            builder.timeField(LAST_REFRESHED_TIME_FIELD, String.format(Locale.getDefault(), "%s_in_millis",
                    LAST_REFRESHED_TIME_FIELD), lastRefreshedTime.toEpochMilli());
        }
        if (lastRefreshedUser == null) {
            builder.nullField(LAST_REFRESHED_USER_FIELD);
        } else {
            builder.field(LAST_REFRESHED_USER_FIELD, lastRefreshedUser);
        }
        builder.field(ENABLED_FIELD, isEnabled);
        builder.field(IOC_TYPES_FIELD, iocTypes);
        builder.endObject();
        builder.endObject();
        return builder;
    }

    public static SATIFSourceConfigDto docParse(XContentParser xcp, String id, Long version) throws IOException {
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        SATIFSourceConfigDto saTifSourceConfigDto = parse(xcp, id, version);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, xcp.nextToken(), xcp);

        saTifSourceConfigDto.setId(id);
        saTifSourceConfigDto.setVersion(version);
        return saTifSourceConfigDto;
    }

    public static SATIFSourceConfigDto parse(XContentParser xcp, String id, Long version) throws IOException {
        if (version == null) {
            version = NO_VERSION;
        }

        String name = null;
        String format = null;
        SourceConfigType sourceConfigType = null;
        String description = null;
        User createdByUser = null;
        Instant createdAt = null;
        Source source = null;
        Instant enabledTime = null;
        Instant lastUpdateTime = null;
        Schedule schedule = null;
        TIFJobState state = null;
        RefreshType refreshType = null;
        Instant lastRefreshedTime = null;
        User lastRefreshedUser = null;
        Boolean isEnabled = null;
        List<String> iocTypes = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case SOURCE_CONFIG_FIELD:
                    break;
                case NAME_FIELD:
                    name = xcp.text();
                    break;
                case FORMAT_FIELD:
                    format = xcp.text();
                    break;
                case TYPE_FIELD:
                    sourceConfigType = toSourceConfigType(xcp.text());
                    break;
                case DESCRIPTION_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        description = null;
                    } else {
                        description = xcp.text();
                    }
                    break;
                case CREATED_BY_USER_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        createdByUser = null;
                    } else {
                        createdByUser = User.parse(xcp);
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
                case SOURCE_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        source = null;
                    } else {
                        source = Source.parse(xcp);
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
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        schedule = null;
                    } else {
                        schedule = ScheduleParser.parse(xcp);
                    }
                    break;
                case STATE_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        state = TIFJobState.CREATING;
                    } else {
                        state = toState(xcp.text());
                    }
                    break;
                case REFRESH_TYPE_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        refreshType = null;
                    } else {
                        refreshType = toRefreshType(xcp.text());
                    }
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
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        lastRefreshedUser = null;
                    } else {
                        lastRefreshedUser = User.parse(xcp);
                    }
                    break;
                case ENABLED_FIELD:
                    isEnabled = xcp.booleanValue();
                    break;
                case IOC_TYPES_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        iocTypes.add(xcp.text());
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        if (isEnabled && enabledTime == null) {
            enabledTime = Instant.now();
        } else if (!isEnabled) {
            enabledTime = null;
        }

        return new SATIFSourceConfigDto(
                id,
                version,
                name,
                format,
                sourceConfigType,
                description,
                createdByUser,
                createdAt != null ? createdAt : Instant.now(),
                source,
                enabledTime,
                lastUpdateTime != null ? lastUpdateTime : Instant.now(),
                schedule,
                state,
                refreshType,
                lastRefreshedTime,
                lastRefreshedUser,
                isEnabled,
                iocTypes
        );
    }

    // TODO: refactor out to sa commons
    public static TIFJobState toState(String stateName) {
        try {
            return TIFJobState.valueOf(stateName);
        } catch (IllegalArgumentException e) {
            log.error("Invalid state, cannot be parsed.", e);
            return null;
        }
    }

    public static SourceConfigType toSourceConfigType(String type) {
        try {
            return SourceConfigType.valueOf(type);
        } catch (IllegalArgumentException e) {
            log.error("Invalid source config type, cannot be parsed.", e);
            return null;
        }
    }

    public static RefreshType toRefreshType(String stateName) {
        try {
            return RefreshType.valueOf(stateName);
        } catch (IllegalArgumentException e) {
            log.error("Invalid refresh type, cannot be parsed.", e);
            return null;
        }
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
        return this.name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getFormat() {
        return format;
    }
    public void setFormat(String format) {
        this.format = format;
    }
    public SourceConfigType getType() {
        return type;
    }
    public void setType(SourceConfigType type) {
        this.type = type;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public User getCreatedByUser() {
        return createdByUser;
    }
    public void setCreatedByUser(User createdByUser) {
        this.createdByUser = createdByUser;
    }
    public Instant getCreatedAt() {
        return createdAt;
    }
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Source getSource() {
        return source;
    }

    public void setSource(Source source) {
        this.source = source;
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
    public User getLastRefreshedUser() {
        return lastRefreshedUser;
    }
    public void setLastRefreshedUser(User lastRefreshedUser) {
        this.lastRefreshedUser = lastRefreshedUser;
    }
    public Instant getLastRefreshedTime() {
        return lastRefreshedTime;
    }
    public void setLastRefreshedTime(Instant lastRefreshedTime) {
        this.lastRefreshedTime = lastRefreshedTime;
    }
    public RefreshType getRefreshType() {
        return refreshType;
    }
    public void setRefreshType(RefreshType refreshType) {
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

    public List<String> getIocTypes() {
        return iocTypes;
    }

    public void setIocTypes(List<String> iocTypes) {
        this.iocTypes = iocTypes;
    }

    public static SATIFSourceConfigDto readFrom(StreamInput sin) throws IOException {
        return new SATIFSourceConfigDto(sin);
    }
}