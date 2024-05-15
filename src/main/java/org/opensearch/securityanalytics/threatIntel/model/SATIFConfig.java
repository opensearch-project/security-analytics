/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.threatIntel.model;

import org.opensearch.common.lucene.uid.Versions;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.jobscheduler.spi.schedule.Schedule;
import org.opensearch.jobscheduler.spi.schedule.ScheduleParser;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;

import java.io.IOException;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;

import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;


public class SATIFConfig implements Writeable, ScheduledJobParameter {
    /**
     * Prefix of indices having threatIntel data
     */
    public static final String THREAT_INTEL_DATA_INDEX_NAME_PREFIX = ".opensearch-sap-threat-intel";

    /**
     * String fields for job scheduling parameters used for ParseField
     */

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
    public static final String REFRESH_STATS_FIELD = "refresh_stats";
    public static final String ENABLED_FIELD = "enabled";
    public static final String INDICES_FIELD = "indices"; // TODO: rename
    public static final String UPDATE_STATS_FIELD = "update_stats";

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
    private RefreshStats refreshStats;

    private Boolean isEnabled;
    private Map<String, Object> indices;
    private UpdateStats updateStats;

    public SATIFConfig(String id, Long version, String feedName, String feedFormatId, Boolean prepackaged, String createdByUser, Instant createdAt,
                       Instant enabledTime, Instant lastUpdateTime, Schedule schedule, TIFJobState state, RefreshStats refreshStats,
                       Boolean isEnabled, Map<String, Object> indices, UpdateStats updateStats) {
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
        this.refreshStats = refreshStats;
        this.isEnabled = isEnabled;
        this.indices = indices;
        this.updateStats = updateStats;
    }

    public SATIFConfig(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(),
                sin.readString(),
                sin.readString(),
                sin.readBoolean(),
                sin.readString(),
                sin.readInstant(),
                sin.readInstant(),
                sin.readInstant(),
                new IntervalSchedule(sin),
                TIFJobState.valueOf(sin.readString()),
                new RefreshStats(sin),
                sin.readBoolean(),
                sin.readMap(),
                new UpdateStats(sin)
        );
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
        refreshStats.writeTo(out);
        out.writeBoolean(isEnabled);
        out.writeMap(indices);
        updateStats.writeTo(out);
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
        builder.field(REFRESH_STATS_FIELD, refreshStats);
        builder.field(ENABLED_FIELD, isEnabled);
        builder.field(INDICES_FIELD, indices);
        builder.field(UPDATE_STATS_FIELD, updateStats);

        builder.endObject();
        return builder;
    }

    public static SATIFConfig parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = NO_ID;
        }
        if (version == null) {
            version = NO_VERSION;
        }

        String feedName = null;
        String feedFormatId = null;
        Boolean prepackaged = true;
        String createdByUser = null;
        Instant createdAt = null;
        Instant enabledTime = null;
        Instant lastUpdateTime = null;
        Schedule schedule = null;
        TIFJobState state = null;
        RefreshStats refreshStats = null;
        Boolean isEnabled = null;
        Map<String,Object> indices = null;
        UpdateStats updateStats = null;

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
                    feedFormatId = xcp.text();
                    break;
                case PREPACKAGED_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        prepackaged = false;
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
                case REFRESH_STATS_FIELD:
                    if (xcp.currentToken() != XContentParser.Token.VALUE_NULL) {
                        refreshStats = new RefreshStats();;
                    } else {
                        refreshStats = RefreshStats.parse(xcp);
                    }
                case ENABLED_FIELD:
                    isEnabled = xcp.booleanValue();
                    break;
                case INDICES_FIELD:
                    indices = xcp.map();
                    break;
                case UPDATE_STATS_FIELD:
                    if (xcp.currentToken() != XContentParser.Token.VALUE_NULL) {
                        updateStats = new UpdateStats();;
                    } else {
                        updateStats = UpdateStats.parse(xcp);
                    }
                default:
                    xcp.skipChildren();
            }
        }

        if (isEnabled && enabledTime == null) {
            enabledTime = Instant.now();
        } else if (!isEnabled) {
            enabledTime = null;
        }

        return new SATIFConfig(
                id,
                version,
                feedName,
                feedFormatId,
                prepackaged,
                createdByUser,
                createdAt != null ? createdAt : Instant.now(),
                enabledTime,
                lastUpdateTime != null ? lastUpdateTime : Instant.now(),
                schedule,
                state,
                refreshStats,
                isEnabled,
                indices,
                updateStats
        );
    }

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
    @Override
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
    @Override
    public Instant getEnabledTime() {
        return this.enabledTime;
    }

    public void setEnabledTime(Instant enabledTime) {
        this.enabledTime = enabledTime;
    }
    @Override
    public Instant getLastUpdateTime() {
        return this.lastUpdateTime;
    }

    public void setLastUpdateTime(Instant lastUpdateTime) {
        this.lastUpdateTime = lastUpdateTime;
    }
    @Override
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
    @Override
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

    public Map<String, Object> getIndices() {
        return indices;
    }
    public void setIndices(Map<String, Object> indices) {
        this.indices = indices;
    }

    @Override
    public Long getLockDurationSeconds() {
        return TIFLockService.LOCK_DURATION_IN_SECONDS;
    }

    /**
     * Update stats of a tif job
     */
    public static class RefreshStats implements Writeable, ToXContent {
        public static final String REFRESH_TYPE_FIELD = "refresh_type";
        public static final String LAST_REFRESHED_TIME_FIELD = "last_refreshed_time";
        public static final String LAST_REFRESHED_USER_FIELD = "last_refreshed_user";

        public String refreshType;
        public Instant lastRefreshedTime;
        public String lastRefreshedUser;

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

        public RefreshStats(String refreshType, Instant lastRefreshedTime, String lastRefreshedUser) {
            this.refreshType = refreshType;
            this.lastRefreshedTime = lastRefreshedTime;
            this.lastRefreshedUser = lastRefreshedUser;
        }

        public RefreshStats(final StreamInput sin) throws IOException {
            this(
                    sin.readString(),
                    sin.readOptionalInstant(),
                    sin.readOptionalString()
            );
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            out.writeString(refreshType);
            out.writeOptionalInstant(lastRefreshedTime == null ? null : lastRefreshedTime);
            out.writeOptionalString(lastRefreshedUser == null? null : lastRefreshedUser);
        }

        @Override
        public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
            builder.startObject();
            builder.field(REFRESH_TYPE_FIELD, refreshType);
            if (lastRefreshedTime == null) {
                builder.nullField(LAST_REFRESHED_TIME_FIELD);
            } else {
                builder.timeField(LAST_REFRESHED_TIME_FIELD, String.format(Locale.getDefault(), "%s_in_millis",
                        LAST_REFRESHED_TIME_FIELD), lastRefreshedTime.toEpochMilli());
            }
            builder.field(LAST_REFRESHED_USER_FIELD, lastRefreshedUser);
            builder.endObject();
            return builder;
        }
        private RefreshStats() {
        }
        public static RefreshStats parse(XContentParser xcp) throws IOException {
            String refreshType = null;
            Instant lastRefreshedTime = null;
            String lastRefreshedUser = null;

            xcp.nextToken();
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
            while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
                String fieldName = xcp.currentName();
                xcp.nextToken();

                switch (fieldName) {
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
                    default:
                        xcp.skipChildren();
                }
            }

            return new RefreshStats(refreshType, lastRefreshedTime, lastRefreshedUser);
        }
    }

    /**
     * Update stats of a tif job
     */
    public static class UpdateStats implements Writeable, ToXContent {
        private static final String LAST_FAILED_AT_IN_EPOCH_MILLIS_FIELD = "last_failed_at_in_epoch_millis";
        private static final String LAST_PROCESSING_TIME_IN_MILLIS_FIELD = "last_processing_time_in_millis";
        private static final String LAST_SKIPPED_AT_IN_EPOCH_MILLIS_FIELD = "last_skipped_at_in_epoch_millis";
        private static final String LAST_SUCCEEDED_AT_IN_EPOCH_MILLIS_FIELD = "last_succeeded_at_in_epoch_millis";

        private Instant lastFailedAt;
        private Long lastProcessingTimeInMillis;
        private Instant lastSkippedAt;
        private Instant lastSucceededAt;

        public Instant getLastSucceededAt() {
            return lastSucceededAt;
        }
        public void setLastSucceededAt(Instant lastSucceededAt) {
            this.lastSucceededAt = lastSucceededAt;
        }
        public Long getLastProcessingTimeInMillis() {
            return lastProcessingTimeInMillis;
        }
        public void setLastProcessingTimeInMillis(Long lastProcessingTimeInMillis) {
            this.lastProcessingTimeInMillis = lastProcessingTimeInMillis;
        }
        public Instant getLastSkippedAt() {
            return lastSkippedAt;
        }
        public void setLastSkippedAt(Instant lastSkippedAt) {
            this.lastSkippedAt = lastSkippedAt;
        }
        public Instant getLastFailedAt() {
            return lastFailedAt;
        }
        public void setLastFailedAt(Instant now) {
            this.lastFailedAt = now;
        }
        public UpdateStats(Instant lastFailedAt, Long lastProcessingTimeInMillis, Instant lastSkippedAt, Instant lastSucceededAt) {
            this.lastFailedAt = lastFailedAt;
            this.lastProcessingTimeInMillis = lastProcessingTimeInMillis;
            this.lastSkippedAt = lastSkippedAt;
            this.lastSucceededAt = lastSucceededAt;
        }

        private UpdateStats() {
        }

        public UpdateStats(final StreamInput sin) throws IOException {
            lastFailedAt = sin.readOptionalInstant();
            lastProcessingTimeInMillis = sin.readOptionalVLong();
            lastSkippedAt = sin.readOptionalInstant();
            lastSucceededAt = sin.readOptionalInstant();
        }
        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            out.writeOptionalInstant(lastFailedAt == null ? null : lastFailedAt);
            out.writeOptionalVLong(lastProcessingTimeInMillis);
            out.writeOptionalInstant(lastSkippedAt == null ? null : lastSkippedAt);
            out.writeOptionalInstant(lastSucceededAt == null ? null : lastSucceededAt);
        }
        @Override
        public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
            builder.startObject();
            if (lastFailedAt == null) {
                builder.nullField(LAST_FAILED_AT_IN_EPOCH_MILLIS_FIELD);
            } else {
                builder.timeField(LAST_FAILED_AT_IN_EPOCH_MILLIS_FIELD, String.format(Locale.getDefault(), "%s_in_millis",
                        LAST_FAILED_AT_IN_EPOCH_MILLIS_FIELD), lastFailedAt.toEpochMilli());
            }

            if (lastProcessingTimeInMillis == null) {
                builder.nullField(LAST_PROCESSING_TIME_IN_MILLIS_FIELD);
            } else {
                builder.timeField(LAST_PROCESSING_TIME_IN_MILLIS_FIELD, String.format(Locale.getDefault(), "%s_in_millis",
                        LAST_PROCESSING_TIME_IN_MILLIS_FIELD), lastProcessingTimeInMillis);
            }

            if (lastSkippedAt == null) {
                builder.nullField(LAST_SKIPPED_AT_IN_EPOCH_MILLIS_FIELD);
            } else {
                builder.timeField(LAST_SKIPPED_AT_IN_EPOCH_MILLIS_FIELD, String.format(Locale.getDefault(), "%s_in_millis",
                        LAST_SKIPPED_AT_IN_EPOCH_MILLIS_FIELD), lastSkippedAt.toEpochMilli());
            }

            if (lastSucceededAt == null) {
                builder.nullField(LAST_SUCCEEDED_AT_IN_EPOCH_MILLIS_FIELD);
            } else {
                builder.timeField(LAST_SUCCEEDED_AT_IN_EPOCH_MILLIS_FIELD, String.format(Locale.getDefault(), "%s_in_millis",
                        LAST_SUCCEEDED_AT_IN_EPOCH_MILLIS_FIELD), lastSucceededAt.toEpochMilli());
            }

            builder.endObject();
            return builder;
        }

        public static UpdateStats parse(XContentParser xcp) throws IOException {
            Instant lastFailedAt = null;
            Long lastProcessingTimeInMillis = null;
            Instant lastSkippedAt = null;
            Instant lastSucceededAt = null;


            xcp.nextToken();
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
            while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
                String fieldName = xcp.currentName();
                xcp.nextToken();

                switch (fieldName) {
                    case LAST_FAILED_AT_IN_EPOCH_MILLIS_FIELD:
                        if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                            lastFailedAt = null;
                        } else if (xcp.currentToken().isValue()) {
                            lastFailedAt = Instant.ofEpochMilli(xcp.longValue());
                        } else {
                            XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                            lastFailedAt = null;
                        }
                        break;
                    case LAST_PROCESSING_TIME_IN_MILLIS_FIELD:
                        if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                            lastProcessingTimeInMillis = null;
                        } else if (xcp.currentToken().isValue()) {
                            lastProcessingTimeInMillis = xcp.longValue();
                        } else {
                            XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                            lastProcessingTimeInMillis = null;
                        }
                        break;
                    case LAST_SKIPPED_AT_IN_EPOCH_MILLIS_FIELD:
                        if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                            lastSkippedAt = null;
                        } else if (xcp.currentToken().isValue()) {
                            lastSkippedAt = Instant.ofEpochMilli(xcp.longValue());
                        } else {
                            XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                            lastSkippedAt = null;
                        }
                        break;
                    case LAST_SUCCEEDED_AT_IN_EPOCH_MILLIS_FIELD:
                        if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                            lastSucceededAt = null;
                        } else if (xcp.currentToken().isValue()) {
                            lastSucceededAt = Instant.ofEpochMilli(xcp.longValue());
                        } else {
                            XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                            lastSucceededAt = null;
                        }
                        break;
                    default:
                        xcp.skipChildren();
                }
            }

            return new UpdateStats(lastFailedAt, lastProcessingTimeInMillis, lastSkippedAt, lastSucceededAt);
        }

    }

}