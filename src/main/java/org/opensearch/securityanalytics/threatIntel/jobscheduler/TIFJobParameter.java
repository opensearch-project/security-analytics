/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ConstructingObjectParser;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.jobscheduler.spi.schedule.ScheduleParser;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.opensearch.common.time.DateUtils.toInstant;

import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.PutTIFJobRequest;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;

public class TIFJobParameter implements Writeable, ScheduledJobParameter {
    /**
     * Prefix of indices having threatIntel data
     */
    public static final String THREAT_INTEL_DATA_INDEX_NAME_PREFIX = ".opensearch-sap-threatintel";

    /**
     * Default fields for job scheduling
     */
    private static final ParseField NAME_FIELD = new ParseField("name");
    private static final ParseField ENABLED_FIELD = new ParseField("update_enabled");
    private static final ParseField LAST_UPDATE_TIME_FIELD = new ParseField("last_update_time");
    private static final ParseField LAST_UPDATE_TIME_FIELD_READABLE = new ParseField("last_update_time_field");
    public static final ParseField SCHEDULE_FIELD = new ParseField("schedule");
    private static final ParseField ENABLED_TIME_FIELD = new ParseField("enabled_time");
    private static final ParseField ENABLED_TIME_FIELD_READABLE = new ParseField("enabled_time_field");

    /**
     * Additional fields for tif job
     */
    private static final ParseField STATE_FIELD = new ParseField("state");
    private static final ParseField INDICES_FIELD = new ParseField("indices");
    private static final ParseField UPDATE_STATS_FIELD = new ParseField("update_stats");


    /**
     * Default variables for job scheduling
     */

    /**
     * @param name name of a tif job
     * @return name of a tif job
     */
    private String name;

    /**
     * @param lastUpdateTime Last update time of a tif job
     * @return Last update time of a tif job
     */
    private Instant lastUpdateTime;
    /**
     * @param enabledTime Last time when a scheduling is enabled for a threat intel feed data update
     * @return Last time when a scheduling is enabled for the job scheduler
     */
    private Instant enabledTime;
    /**
     * @param isEnabled Indicate if threat intel feed data update is scheduled or not
     * @return Indicate if scheduling is enabled or not
     */
    private boolean isEnabled;
    /**
     * @param schedule Schedule that system uses
     * @return Schedule that system uses
     */
    private IntervalSchedule schedule;


    /**
     * Additional variables for tif job
     */

    /**
     * @param state State of a tif job
     * @return State of a tif job
     */
    private TIFJobState state;

    /**
     * @param indices A list of indices having threat intel feed data
     * @return A list of indices having threat intel feed data including
     */
    private List<String> indices;

    /**
     * @param updateStats threat intel feed database update statistics
     * @return threat intel feed database update statistics
     */
    private UpdateStats updateStats;

    /**
     * tif job parser
     */
    public static final ConstructingObjectParser<TIFJobParameter, Void> PARSER = new ConstructingObjectParser<>(
            "tifjob_metadata",
            true,
            args -> {
                String name = (String) args[0];
                Instant lastUpdateTime = Instant.ofEpochMilli((long) args[1]);
                Instant enabledTime = args[2] == null ? null : Instant.ofEpochMilli((long) args[2]);
                boolean isEnabled = (boolean) args[3];
                IntervalSchedule schedule = (IntervalSchedule) args[4];
                TIFJobState state = TIFJobState.valueOf((String) args[5]);
                List<String> indices = (List<String>) args[6];
                UpdateStats updateStats = (UpdateStats) args[7];
                TIFJobParameter parameter = new TIFJobParameter(
                    name,
                    lastUpdateTime,
                    enabledTime,
                    isEnabled,
                    schedule,
                    state,
                    indices,
                    updateStats
                );
                return parameter;
            }
    );
    static {
        PARSER.declareString(ConstructingObjectParser.constructorArg(), NAME_FIELD);
        PARSER.declareLong(ConstructingObjectParser.constructorArg(), LAST_UPDATE_TIME_FIELD);
        PARSER.declareLong(ConstructingObjectParser.optionalConstructorArg(), ENABLED_TIME_FIELD);
        PARSER.declareBoolean(ConstructingObjectParser.constructorArg(), ENABLED_FIELD);
        PARSER.declareObject(ConstructingObjectParser.constructorArg(), (p, c) -> ScheduleParser.parse(p), SCHEDULE_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), STATE_FIELD);
        PARSER.declareStringArray(ConstructingObjectParser.constructorArg(), INDICES_FIELD);
        PARSER.declareObject(ConstructingObjectParser.constructorArg(), UpdateStats.PARSER, UPDATE_STATS_FIELD);
    }

    public TIFJobParameter() {
        this(null, null);
    }

    public TIFJobParameter(final String name, final Instant lastUpdateTime, final Instant enabledTime, final Boolean isEnabled,
                           final IntervalSchedule schedule, final TIFJobState state,
                           final List<String> indices, final UpdateStats updateStats) {
        this.name = name;
        this.lastUpdateTime = lastUpdateTime;
        this.enabledTime = enabledTime;
        this.isEnabled = isEnabled;
        this.schedule = schedule;
        this.state = state;
        this.indices = indices;
        this.updateStats = updateStats;
    }

    public TIFJobParameter(final String name, final IntervalSchedule schedule) {
        this(
                name,
                Instant.now().truncatedTo(ChronoUnit.MILLIS),
                null,
                false,
                schedule,
                TIFJobState.CREATING,
                new ArrayList<>(),
                new UpdateStats()
        );
    }

    public TIFJobParameter(final StreamInput in) throws IOException {
        name = in.readString();
        lastUpdateTime = toInstant(in.readVLong());
        enabledTime = toInstant(in.readOptionalVLong());
        isEnabled = in.readBoolean();
        schedule = new IntervalSchedule(in);
        state = TIFJobState.valueOf(in.readString());
        indices = in.readStringList();
        updateStats = new UpdateStats(in);
    }

    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeVLong(lastUpdateTime.toEpochMilli());
        out.writeOptionalVLong(enabledTime == null ? null : enabledTime.toEpochMilli());
        out.writeBoolean(isEnabled);
        schedule.writeTo(out);
        out.writeString(state.name());
        out.writeStringCollection(indices);
        updateStats.writeTo(out);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject();
        builder.field(NAME_FIELD.getPreferredName(), name);
        builder.timeField(
                LAST_UPDATE_TIME_FIELD.getPreferredName(),
                LAST_UPDATE_TIME_FIELD_READABLE.getPreferredName(),
                lastUpdateTime.toEpochMilli()
        );
        if (enabledTime != null) {
            builder.timeField(
                    ENABLED_TIME_FIELD.getPreferredName(),
                    ENABLED_TIME_FIELD_READABLE.getPreferredName(),
                    enabledTime.toEpochMilli()
            );
        }
        builder.field(ENABLED_FIELD.getPreferredName(), isEnabled);
        builder.field(SCHEDULE_FIELD.getPreferredName(), schedule);
        builder.field(STATE_FIELD.getPreferredName(), state.name());
        builder.field(INDICES_FIELD.getPreferredName(), indices);
        builder.field(UPDATE_STATS_FIELD.getPreferredName(), updateStats);
        builder.endObject();
        return builder;
    }

    // getters and setters
    public void setName(String name) {
        this.name = name;
    }
    public void setEnabledTime(Instant enabledTime) {
        this.enabledTime = enabledTime;
    }

    public void setEnabled(boolean enabled) {
        isEnabled = enabled;
    }

    public void setIndices(List<String> indices) {
        this.indices = indices;
    }

    @Override
    public String getName() {
        return this.name;
    }
    @Override
    public Instant getLastUpdateTime() {
        return this.lastUpdateTime;
    }
    @Override
    public Instant getEnabledTime() {
        return this.enabledTime;
    }
    @Override
    public IntervalSchedule getSchedule() {
        return this.schedule;
    }
    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

    public void setLastUpdateTime(Instant lastUpdateTime) {
        this.lastUpdateTime = lastUpdateTime;
    }

    @Override
    public Long getLockDurationSeconds() {
        return TIFLockService.LOCK_DURATION_IN_SECONDS;
    }

    /**
     * Enable auto update of threat intel feed data
     */
    public void enable() {
        if (isEnabled == true) {
            return;
        }
        enabledTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        isEnabled = true;
    }

    /**
     * Disable auto update of threat intel feed data
     */
    public void disable() {
        enabledTime = null;
        isEnabled = false;
    }

    public void setSchedule(IntervalSchedule schedule) {
        this.schedule = schedule;
    }

    /**
     * Index name for a tif job
     *
     * @return index name for a tif job
     */
    public String newIndexName(final TIFJobParameter jobSchedulerParameter, TIFMetadata tifMetadata) {
        List<String> indices = jobSchedulerParameter.getIndices();
        Optional<String> nameOptional = indices.stream().filter(name -> name.contains(tifMetadata.getFeedId())).findAny();
        String suffix = "-1";
        if (nameOptional.isPresent()) {
            suffix = "-1".equals(nameOptional.get()) ? "-2" : suffix;
        }
        return String.format(Locale.ROOT, "%s-%s-%s", THREAT_INTEL_DATA_INDEX_NAME_PREFIX, tifMetadata.getFeedId(), suffix);
    }

    public TIFJobState getState() {
        return state;
    }

    public List<String> getIndices() {
        return indices;
    }

    public void setState(TIFJobState previousState) {
        this.state = previousState;
    }

    public UpdateStats getUpdateStats() {
        return this.updateStats;
    }


    /**
     * Update stats of a tif job
     */
    public static class UpdateStats implements Writeable, ToXContent {
        private static final ParseField LAST_SUCCEEDED_AT_FIELD = new ParseField("last_succeeded_at_in_epoch_millis");
        private static final ParseField LAST_SUCCEEDED_AT_FIELD_READABLE = new ParseField("last_succeeded_at");
        private static final ParseField LAST_PROCESSING_TIME_IN_MILLIS_FIELD = new ParseField("last_processing_time_in_millis");
        private static final ParseField LAST_FAILED_AT_FIELD = new ParseField("last_failed_at_in_epoch_millis");
        private static final ParseField LAST_FAILED_AT_FIELD_READABLE = new ParseField("last_failed_at");
        private static final ParseField LAST_SKIPPED_AT = new ParseField("last_skipped_at_in_epoch_millis");
        private static final ParseField LAST_SKIPPED_AT_READABLE = new ParseField("last_skipped_at");

        public Instant getLastSucceededAt() {
            return lastSucceededAt;
        }

        public Long getLastProcessingTimeInMillis() {
            return lastProcessingTimeInMillis;
        }

        public Instant getLastFailedAt() {
            return lastFailedAt;
        }

        public Instant getLastSkippedAt() {
            return lastSkippedAt;
        }

        /**
         * @param lastSucceededAt The last time when threat intel feed data update was succeeded
         * @return The last time when threat intel feed data update was succeeded
         */
        private Instant lastSucceededAt;
        /**
         * @param lastProcessingTimeInMillis The last processing time when threat intel feed data update was succeeded
         * @return The last processing time when threat intel feed data update was succeeded
         */
        private Long lastProcessingTimeInMillis;
        /**
         * @param lastFailedAt The last time when threat intel feed data update was failed
         * @return The last time when threat intel feed data update was failed
         */
        private Instant lastFailedAt;

        /**
         * @param lastSkippedAt The last time when threat intel feed data update was skipped as there was no new update from an endpoint
         * @return The last time when threat intel feed data update was skipped as there was no new update from an endpoint
         */
        private Instant lastSkippedAt;

        private UpdateStats(){}

        public void setLastSkippedAt(Instant lastSkippedAt) {
            this.lastSkippedAt = lastSkippedAt;
        }

        public void setLastSucceededAt(Instant lastSucceededAt) {
            this.lastSucceededAt = lastSucceededAt;
        }

        public void setLastProcessingTimeInMillis(Long lastProcessingTimeInMillis) {
            this.lastProcessingTimeInMillis = lastProcessingTimeInMillis;
        }

        private static final ConstructingObjectParser<UpdateStats, Void> PARSER = new ConstructingObjectParser<>(
                "tifjob_metadata_update_stats",
                true,
                args -> {
                    Instant lastSucceededAt = args[0] == null ? null : Instant.ofEpochMilli((long) args[0]);
                    Long lastProcessingTimeInMillis = (Long) args[1];
                    Instant lastFailedAt = args[2] == null ? null : Instant.ofEpochMilli((long) args[2]);
                    Instant lastSkippedAt = args[3] == null ? null : Instant.ofEpochMilli((long) args[3]);
                    return new UpdateStats(lastSucceededAt, lastProcessingTimeInMillis, lastFailedAt, lastSkippedAt);
                }
        );
        static {
            PARSER.declareLong(ConstructingObjectParser.optionalConstructorArg(), LAST_SUCCEEDED_AT_FIELD);
            PARSER.declareLong(ConstructingObjectParser.optionalConstructorArg(), LAST_PROCESSING_TIME_IN_MILLIS_FIELD);
            PARSER.declareLong(ConstructingObjectParser.optionalConstructorArg(), LAST_FAILED_AT_FIELD);
            PARSER.declareLong(ConstructingObjectParser.optionalConstructorArg(), LAST_SKIPPED_AT);
        }

        public UpdateStats(final StreamInput in) throws IOException {
            lastSucceededAt = toInstant(in.readOptionalVLong());
            lastProcessingTimeInMillis = in.readOptionalVLong();
            lastFailedAt = toInstant(in.readOptionalVLong());
            lastSkippedAt = toInstant(in.readOptionalVLong());
        }

        public UpdateStats(Instant lastSucceededAt, Long lastProcessingTimeInMillis, Instant lastFailedAt, Instant lastSkippedAt) {
            this.lastSucceededAt = lastSucceededAt;
            this.lastProcessingTimeInMillis = lastProcessingTimeInMillis;
            this.lastFailedAt = lastFailedAt;
            this.lastSkippedAt = lastSkippedAt;
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            out.writeOptionalVLong(lastSucceededAt == null ? null : lastSucceededAt.toEpochMilli());
            out.writeOptionalVLong(lastProcessingTimeInMillis);
            out.writeOptionalVLong(lastFailedAt == null ? null : lastFailedAt.toEpochMilli());
            out.writeOptionalVLong(lastSkippedAt == null ? null : lastSkippedAt.toEpochMilli());
        }

        @Override
        public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
            builder.startObject();
            if (lastSucceededAt != null) {
                builder.timeField(
                        LAST_SUCCEEDED_AT_FIELD.getPreferredName(),
                        LAST_SUCCEEDED_AT_FIELD_READABLE.getPreferredName(),
                        lastSucceededAt.toEpochMilli()
                );
            }
            if (lastProcessingTimeInMillis != null) {
                builder.field(LAST_PROCESSING_TIME_IN_MILLIS_FIELD.getPreferredName(), lastProcessingTimeInMillis);
            }
            if (lastFailedAt != null) {
                builder.timeField(
                        LAST_FAILED_AT_FIELD.getPreferredName(),
                        LAST_FAILED_AT_FIELD_READABLE.getPreferredName(),
                        lastFailedAt.toEpochMilli()
                );
            }
            if (lastSkippedAt != null) {
                builder.timeField(
                        LAST_SKIPPED_AT.getPreferredName(),
                        LAST_SKIPPED_AT_READABLE.getPreferredName(),
                        lastSkippedAt.toEpochMilli()
                );
            }
            builder.endObject();
            return builder;
        }

        public void setLastFailedAt(Instant now) {
            this.lastFailedAt = now;
        }
    }

    /**
     * Builder class for tif job
     */
    public static class Builder {
        public static TIFJobParameter build(final PutTIFJobRequest request) {
            String name = request.getName();
            IntervalSchedule schedule = new IntervalSchedule(
                    Instant.now().truncatedTo(ChronoUnit.MILLIS),
                    SecurityAnalyticsSettings.tifJobScheduleInterval,
                    ChronoUnit.DAYS
            );
            return new TIFJobParameter(name, schedule);

        }
    }
}