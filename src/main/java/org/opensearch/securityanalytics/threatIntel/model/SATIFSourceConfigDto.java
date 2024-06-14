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
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.jobscheduler.spi.schedule.ScheduleParser;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.common.RefreshType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.sacommons.TIFSourceConfigDto;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Implementation of TIF Config Dto to store the feed configuration metadata as DTO object
 */
public class SATIFSourceConfigDto implements Writeable, ToXContentObject, TIFSourceConfigDto {

    private static final Logger log = LogManager.getLogger(SATIFSourceConfigDto.class);

    public static final String FEED_SOURCE_CONFIG_FIELD = "feed_source_config";

    public static final String NO_ID = "";

    public static final Long NO_VERSION = 1L;
    public static final String VERSION_FIELD = "version";
    public static final String FEED_NAME_FIELD = "feed_name";
    public static final String FEED_FORMAT_FIELD = "feed_format";
    public static final String FEED_TYPE_FIELD = "feed_type";
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
    private String feedName;
    private String feedFormat;
    private SourceConfigType sourceConfigType;
    private String description;
    private String createdByUser;
    private Instant createdAt;
    private Source source;
    private Instant enabledTime;
    private Instant lastUpdateTime;
    private IntervalSchedule schedule;
    private TIFJobState state;
    public RefreshType refreshType;
    public Instant lastRefreshedTime;
    public String lastRefreshedUser;
    private Boolean isEnabled;
    private List<String> iocTypes;

    public SATIFSourceConfigDto(SATIFSourceConfig SaTifSourceConfig) {
        this.id = SaTifSourceConfig.getId();
        this.version = SaTifSourceConfig.getVersion();
        this.feedName = SaTifSourceConfig.getName();
        this.feedFormat = SaTifSourceConfig.getFeedFormat();
        this.sourceConfigType = SaTifSourceConfig.getSourceConfigType();
        this.description = SaTifSourceConfig.getDescription();
        this.createdByUser = SaTifSourceConfig.getCreatedByUser();
        this.createdAt = SaTifSourceConfig.getCreatedAt();
        this.source = SaTifSourceConfig.getSource();
        this.enabledTime = SaTifSourceConfig.getEnabledTime();
        this.lastUpdateTime = SaTifSourceConfig.getLastUpdateTime();
        this.schedule = SaTifSourceConfig.getSchedule();
        this.state = SaTifSourceConfig.getState();
        this.refreshType = SaTifSourceConfig.getRefreshType();
        this.lastRefreshedTime = SaTifSourceConfig.getLastRefreshedTime();
        this.lastRefreshedUser = SaTifSourceConfig.getLastRefreshedUser();
        this.isEnabled = SaTifSourceConfig.isEnabled();;
        this.iocTypes = SaTifSourceConfig.getIocTypes();
    }

    public SATIFSourceConfigDto(String id, Long version, String feedName, String feedFormat, SourceConfigType sourceConfigType, String description, String createdByUser, Instant createdAt, Source source,
                                Instant enabledTime, Instant lastUpdateTime, IntervalSchedule schedule, TIFJobState state, RefreshType refreshType, Instant lastRefreshedTime, String lastRefreshedUser,
                                Boolean isEnabled, List<String> iocTypes) {
        this.id = id != null ? id : NO_ID;
        this.version = version != null ? version : NO_VERSION;
        this.feedName = feedName;
        this.feedFormat = feedFormat;
        this.sourceConfigType = sourceConfigType;
        this.description = description;
        this.createdByUser = createdByUser;
        this.source = source;
        this.createdAt = createdAt != null ? createdAt : Instant.now();

        if (isEnabled == null && enabledTime == null) {
            this.enabledTime = Instant.now();
        } else if (isEnabled != null && !isEnabled) {
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
                sin.readString(), // feed name
                sin.readString(), // feed format
                SourceConfigType.valueOf(sin.readString()), // feed type
                sin.readOptionalString(), // description
                sin.readOptionalString(), // created by user
                sin.readInstant(), // created at
                Source.readFrom(sin), // source
                sin.readOptionalInstant(), // enabled time
                sin.readInstant(), // last update time
                new IntervalSchedule(sin), // schedule
                TIFJobState.valueOf(sin.readString()), // state
                RefreshType.valueOf(sin.readString()), // state
                sin.readOptionalInstant(), // last refreshed time
                sin.readOptionalString(), // last refreshed user
                sin.readBoolean(), // is enabled
                sin.readStringList() // ioc types
        );
    }

    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeString(feedName);
        out.writeString(feedFormat);
        out.writeString(sourceConfigType.name());
        out.writeOptionalString(description);
        out.writeOptionalString(createdByUser);
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
        out.writeOptionalString(lastRefreshedUser);
        out.writeBoolean(isEnabled);
        out.writeStringCollection(iocTypes);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject()
                .startObject(FEED_SOURCE_CONFIG_FIELD)
                .field(VERSION_FIELD, version)
                .field(FEED_NAME_FIELD, feedName)
                .field(FEED_FORMAT_FIELD, feedFormat)
                .field(FEED_TYPE_FIELD, sourceConfigType.name())
                .field(DESCRIPTION_FIELD, description)
                .field(CREATED_BY_USER_FIELD, createdByUser)
                .field(SOURCE_FIELD, source);

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
        builder.field(LAST_REFRESHED_USER_FIELD, lastRefreshedUser);
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
        SATIFSourceConfigDto SaTifSourceConfigDto = parse(xcp, id, version);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, xcp.nextToken(), xcp);

        SaTifSourceConfigDto.setId(id);
        SaTifSourceConfigDto.setVersion(version);
        return SaTifSourceConfigDto;
    }

    public static SATIFSourceConfigDto parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = NO_ID;
        }
        if (version == null) {
            version = NO_VERSION;
        }

        String feedName = null;
        String feedFormat = null;
        SourceConfigType sourceConfigType = null;
        String description = null;
        String createdByUser = null;
        Instant createdAt = null;
        Source source = null;
        Instant enabledTime = null;
        Instant lastUpdateTime = null;
        IntervalSchedule schedule = null;
        TIFJobState state = null;
        RefreshType refreshType = null;
        Instant lastRefreshedTime = null;
        String lastRefreshedUser = null;
        Boolean isEnabled = null;
        List<String> iocTypes = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case FEED_SOURCE_CONFIG_FIELD:
                    break;
                case FEED_NAME_FIELD:
                    feedName = xcp.text();
                    break;
                case FEED_FORMAT_FIELD:
                    feedFormat = xcp.text();
                    break;
                case FEED_TYPE_FIELD:
                    sourceConfigType = toFeedType(xcp.text());
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
                case SOURCE_FIELD:
                    source = Source.parse(xcp);
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
                        lastRefreshedUser = xcp.text();
                    }
                    break;
                case ENABLED_FIELD:
                    isEnabled = xcp.booleanValue();
                    break;
                case IOC_TYPES_FIELD:
                    iocTypes = new ArrayList<>();
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
                feedName,
                feedFormat,
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

    public static SourceConfigType toFeedType(String feedType) {
        try {
            return SourceConfigType.valueOf(feedType);
        } catch (IllegalArgumentException e) {
            log.error("Invalid feed type, cannot be parsed.", e);
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
    public SourceConfigType getSourceConfigType() {
        return sourceConfigType;
    }
    public void setSourceConfigType(SourceConfigType sourceConfigType) {
        this.sourceConfigType = sourceConfigType;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
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