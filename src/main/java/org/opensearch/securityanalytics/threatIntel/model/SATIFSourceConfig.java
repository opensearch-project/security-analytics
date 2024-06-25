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
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.jobscheduler.spi.schedule.ScheduleParser;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.common.RefreshType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.sacommons.TIFSourceConfig;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;

/**
 * Implementation of TIF Config to store the source configuration metadata and to schedule it onto the job scheduler
 */
public class SATIFSourceConfig implements TIFSourceConfig, Writeable, ScheduledJobParameter {

    private static final Logger log = LogManager.getLogger(SATIFSourceConfig.class);

    /**
     * Prefix of indices having threatIntel data
     */
    public static final String THREAT_INTEL_DATA_INDEX_NAME_PREFIX = ".opensearch-sap-threat-intel";
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
    public static final String IOC_STORE_FIELD = "ioc_store_config";
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
    private IntervalSchedule schedule;
    private TIFJobState state;
    public RefreshType refreshType;
    public Instant lastRefreshedTime;
    public User lastRefreshedUser;
    private Boolean isEnabled;
    private IocStoreConfig iocStoreConfig;
    private List<String> iocTypes;

    public SATIFSourceConfig(String id, Long version, String name, String format, SourceConfigType type, String description, User createdByUser, Instant createdAt, Source source,
                             Instant enabledTime, Instant lastUpdateTime, IntervalSchedule schedule, TIFJobState state, RefreshType refreshType, Instant lastRefreshedTime, User lastRefreshedUser,
                             Boolean isEnabled, IocStoreConfig iocStoreConfig, List<String> iocTypes) {
        this.id = id == null ? UUIDs.base64UUID() : id;
        this.version = version != null ? version : NO_VERSION;
        this.name = name;
        this.format = format;
        this.type = type;
        this.description = description;
        this.createdByUser = createdByUser;
        this.createdAt = createdAt != null ? createdAt : Instant.now();
        this.source = source;

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
        this.iocStoreConfig = iocStoreConfig != null? iocStoreConfig : newIocStoreConfig("default");
        this.iocTypes = iocTypes;
    }

    public SATIFSourceConfig(StreamInput sin) throws IOException {
        this(
                sin.readString(), // id
                sin.readLong(), // version
                sin.readString(), // name
                sin.readString(), // format
                SourceConfigType.valueOf(sin.readString()), // type
                sin.readOptionalString(), // description
                sin.readBoolean()? new User(sin) : null, // created by user
                sin.readInstant(), // created at
                Source.readFrom(sin), // source
                sin.readOptionalInstant(), // enabled time
                sin.readInstant(), // last update time
                new IntervalSchedule(sin), // schedule
                TIFJobState.valueOf(sin.readString()), // state
                RefreshType.valueOf(sin.readString()), // refresh type
                sin.readOptionalInstant(), // last refreshed time
                sin.readBoolean()? new User(sin) : null, // last refreshed user
                sin.readBoolean(), // is enabled
                IocStoreConfig.readFrom(sin), // ioc map store
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
        if (source instanceof S3Source) {
            out.writeEnum(Source.Type.S3);
        }
        source.writeTo(out);
        out.writeOptionalInstant(enabledTime);
        out.writeInstant(lastUpdateTime);
        schedule.writeTo(out);
        out.writeString(state.name());
        out.writeString(refreshType.name());
        out.writeOptionalInstant(lastRefreshedTime);
        out.writeBoolean(lastRefreshedUser != null);
        if (lastRefreshedUser != null) {
            lastRefreshedUser.writeTo(out);
        }
        out.writeBoolean(isEnabled);
        if (iocStoreConfig instanceof DefaultIocStoreConfig) {
            out.writeEnum(IocStoreConfig.Type.DEFAULT);
        }
        iocStoreConfig.writeTo(out);
        out.writeStringCollection(iocTypes);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject()
                .startObject(SOURCE_CONFIG_FIELD)
                .field(VERSION_FIELD, version)
                .field(NAME_FIELD, name)
                .field(FORMAT_FIELD, format)
                .field(TYPE_FIELD, type.name())
                .field(DESCRIPTION_FIELD, description);

        if (createdByUser == null) {
            builder.nullField(CREATED_BY_USER_FIELD);
        } else {
            builder.field(CREATED_BY_USER_FIELD, createdByUser);
        }
        builder.field(SOURCE_FIELD, source);

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
        builder.field(IOC_STORE_FIELD, iocStoreConfig);
        builder.field(IOC_TYPES_FIELD, iocTypes);
        builder.endObject();
        builder.endObject();
        return builder;
    }

    public static SATIFSourceConfig docParse(XContentParser xcp, String id, Long version) throws IOException {
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        SATIFSourceConfig saTifSourceConfig = parse(xcp, id, version);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, xcp.nextToken(), xcp);

        saTifSourceConfig.setId(id);
        saTifSourceConfig.setVersion(version);
        return saTifSourceConfig;
    }

    public static SATIFSourceConfig parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = NO_ID;
        }
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
        IntervalSchedule schedule = null;
        TIFJobState state = null;
        RefreshType refreshType = null;
        Instant lastRefreshedTime = null;
        User lastRefreshedUser = null;
        Boolean isEnabled = null;
        IocStoreConfig iocStoreConfig = null;
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
                case SOURCE_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        source = null;
                    } else {
                        source = Source.parse(xcp);
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
                    schedule = (IntervalSchedule) ScheduleParser.parse(xcp);
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
                case IOC_STORE_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        iocStoreConfig = null;
                    } else {
                        iocStoreConfig = IocStoreConfig.parse(xcp);
                    }
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

        return new SATIFSourceConfig(
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
                iocStoreConfig,
                iocTypes
        );
    }


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

    private IocStoreConfig newIocStoreConfig(String storeType) {
        switch(storeType){
            case "default":
                return new DefaultIocStoreConfig(new HashMap<>());
            default:
                throw new IllegalStateException("Unexpected store type");
        }
    }

    public static SATIFSourceConfig readFrom(StreamInput sin) throws IOException {
        return new SATIFSourceConfig(sin);
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
    public IntervalSchedule getSchedule() {
        return this.schedule;
    }
    public void setSchedule(IntervalSchedule schedule) {
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
    public void enable() {
        if (isEnabled == true) {
            return;
        }
        enabledTime = Instant.now();
        isEnabled = true;
    }
    public void disable() {
        enabledTime = null;
        isEnabled = false;
    }
    public IocStoreConfig getIocStoreConfig() {
        return iocStoreConfig;
    }

    public void setIocStoreConfig(IocStoreConfig iocStoreConfig) {
        this.iocStoreConfig = iocStoreConfig;
    }

    public List<String> getIocTypes() {
        return iocTypes;
    }

    public void setIocTypes(List<String> iocTypes) {
        this.iocTypes = iocTypes;
    }
}