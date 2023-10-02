/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.threatintel.jobscheduler;

import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ConstructingObjectParser;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.jobscheduler.spi.schedule.Schedule;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.jobscheduler.spi.schedule.ScheduleParser;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static org.opensearch.common.time.DateUtils.toInstant;

import org.opensearch.securityanalytics.threatintel.common.DatasourceState;
import org.opensearch.securityanalytics.threatintel.common.ThreatIntelLockService;

public class DatasourceParameter implements ScheduledJobParameter {
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

    // need?
    private static final ParseField TASK_FIELD = new ParseField("task");
    public static final String LOCK_DURATION_SECONDS = "lock_duration_seconds";

    /**
     * Additional fields for datasource
     */
    private static final ParseField ENDPOINT_FIELD = new ParseField("endpoint");
    private static final ParseField STATE_FIELD = new ParseField("state");
    private static final ParseField CURRENT_INDEX_FIELD = new ParseField("current_index");
    private static final ParseField INDICES_FIELD = new ParseField("indices");
    private static final ParseField DATABASE_FIELD = new ParseField("database");
    private static final ParseField UPDATE_STATS_FIELD = new ParseField("update_stats");


    /**
     * Default variables for job scheduling
     */

    /**
     * @param name name of a datasource
     * @return name of a datasource
     */
    private String name;
    /**
     * @param lastUpdateTime Last update time of a datasource
     * @return Last update time of a datasource
     */
    private Instant lastUpdateTime;
    /**
     * @param enabledTime Last time when a scheduling is enabled for a GeoIP data update
     * @return Last time when a scheduling is enabled for the job scheduler
     */
    private Instant enabledTime;
    /**
     * @param isEnabled Indicate if threatIP data update is scheduled or not
     * @return Indicate if scheduling is enabled or not
     */
    private boolean isEnabled;
    /**
     * @param schedule Schedule that system uses
     * @return Schedule that system uses
     */
    private IntervalSchedule schedule;

    /**
     * @param systemSchedule Schedule that job scheduler use
     * @return Schedule that job scheduler use
     */

    // need?
    private DatasourceTask task;


    /**
     * Additional variables for datasource
     */

    /**
     * @param endpoint URL of a manifest file
     * @return URL of a manifest file
     */
    private String endpoint;
    /**
     * @param state State of a datasource
     * @return State of a datasource
     */
    private DatasourceState state;
    /**
     * @param currentIndex the current index name having threatIP data
     * @return the current index name having threatIP data
     */
    private String currentIndex;
    /**
     * @param indices A list of indices having threatIP data including currentIndex
     * @return A list of indices having threatIP data including currentIndex
     */
    private List<String> indices;
    /**
     * @param database threatIP database information
     * @return threatIP database information
     */
//    private Database database;
    /**
     * @param updateStats threatIP database update statistics
     * @return threatIP database update statistics
     */
//    private UpdateStats updateStats;

    /**
     * Datasource parser
     */
    public static final ConstructingObjectParser<DatasourceParameter, Void> PARSER = new ConstructingObjectParser<>(
            "datasource_metadata",
            true,
            args -> {
                String name = (String) args[0];
                Instant lastUpdateTime = Instant.ofEpochMilli((long) args[1]);
                Instant enabledTime = args[2] == null ? null : Instant.ofEpochMilli((long) args[2]);
                boolean isEnabled = (boolean) args[3];
                IntervalSchedule schedule = (IntervalSchedule) args[4];
                DatasourceTask task = DatasourceTask.valueOf((String) args[6]);
                String endpoint = (String) args[7];
                DatasourceState state = DatasourceState.valueOf((String) args[8]);
                String currentIndex = (String) args[9];
                List<String> indices = (List<String>) args[10];
//                Database database = (Database) args[11];
//                UpdateStats updateStats = (UpdateStats) args[12];
                DatasourceParameter parameter = new DatasourceParameter(
                        name,
                        lastUpdateTime,
                        enabledTime,
                        isEnabled,
                        schedule,
                        task,
                        endpoint,
                        state,
                        currentIndex,
                        indices
//                        database,
//                        updateStats
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
        PARSER.declareString(ConstructingObjectParser.constructorArg(), TASK_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), ENDPOINT_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), STATE_FIELD);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), CURRENT_INDEX_FIELD);
        PARSER.declareStringArray(ConstructingObjectParser.constructorArg(), INDICES_FIELD);
//        PARSER.declareObject(ConstructingObjectParser.constructorArg(), Database.PARSER, DATABASE_FIELD);
//        PARSER.declareObject(ConstructingObjectParser.constructorArg(), UpdateStats.PARSER, UPDATE_STATS_FIELD);
    }

    public DatasourceParameter() {
        this(null, null, null);
    }

    public DatasourceParameter(final String name, final IntervalSchedule schedule, final String endpoint) {
        this(
            name,
            Instant.now().truncatedTo(ChronoUnit.MILLIS),
            null,
            false,
            schedule,
            DatasourceTask.ALL,
            endpoint,
            DatasourceState.CREATING,
            null,
            new ArrayList<>()
//            new Database(),
//            new UpdateStats()
        );
    }

    public DatasourceParameter(final StreamInput in) throws IOException {
        name = in.readString();
        lastUpdateTime = toInstant(in.readVLong());
        enabledTime = toInstant(in.readOptionalVLong());
        isEnabled = in.readBoolean();
        schedule = new IntervalSchedule(in);
        task = DatasourceTask.valueOf(in.readString());
        endpoint = in.readString();
        state = DatasourceState.valueOf(in.readString());
        currentIndex = in.readOptionalString();
        indices = in.readStringList();
//        database = new Database(in);
//        updateStats = new UpdateStats(in);
    }

    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeVLong(lastUpdateTime.toEpochMilli());
        out.writeOptionalVLong(enabledTime == null ? null : enabledTime.toEpochMilli());
        out.writeBoolean(isEnabled);
        schedule.writeTo(out);
        out.writeString(task.name());
        out.writeString(endpoint);
        out.writeString(state.name());
        out.writeOptionalString(currentIndex);
        out.writeStringCollection(indices);
//        database.writeTo(out);
//        updateStats.writeTo(out);
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
        builder.field(TASK_FIELD.getPreferredName(), task.name());
        builder.field(ENDPOINT_FIELD.getPreferredName(), endpoint);
        builder.field(STATE_FIELD.getPreferredName(), state.name());
        if (currentIndex != null) {
            builder.field(CURRENT_INDEX_FIELD.getPreferredName(), currentIndex);
        }
        builder.field(INDICES_FIELD.getPreferredName(), indices);
//        builder.field(DATABASE_FIELD.getPreferredName(), database);
//        builder.field(UPDATE_STATS_FIELD.getPreferredName(), updateStats);
        builder.endObject();
        return builder;
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
    public Schedule getSchedule() {
        return this.schedule;
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

    @Override
//    public Long getLockDurationSeconds() {
//        return this.lockDurationSeconds;
//    }
    public Long getLockDurationSeconds() {
        return ThreatIntelLockService.LOCK_DURATION_IN_SECONDS;
    }

    /**
     * Enable auto update of threatIP data
     */
    public void enable() {
        if (isEnabled == true) {
            return;
        }
        enabledTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        isEnabled = true;
    }

    /**
     * Disable auto update of threatIP data
     */
    public void disable() {
        enabledTime = null;
        isEnabled = false;
    }

    /**
     * Current index name of a datasource
     *
     * @return Current index name of a datasource
     */
    public String currentIndexName() {
        return currentIndex;
    }

    public void setSchedule(IntervalSchedule schedule) {
        this.schedule = schedule;
    }

//    /**
//     * Builder class for Datasource
//     */
//    public static class Builder {
//        public static DatasourceParameter build(final PutDatasourceRequest request) {
//            String id = request.getName();
//            IntervalSchedule schedule = new IntervalSchedule(
//                    Instant.now().truncatedTo(ChronoUnit.MILLIS),
//                    (int) request.getUpdateInterval().days(),
//                    ChronoUnit.DAYS
//            );
//            String endpoint = request.getEndpoint();
//            return new DatasourceParameter(id, schedule, endpoint);
//        }
//    }
}