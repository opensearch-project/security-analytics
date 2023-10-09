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

import org.opensearch.securityanalytics.threatIntel.common.DatasourceManifest;
import org.opensearch.securityanalytics.threatIntel.common.DatasourceState;
import org.opensearch.securityanalytics.threatIntel.common.ThreatIntelLockService;

public class Datasource implements Writeable, ScheduledJobParameter {
    /**
     * Prefix of indices having threatIntel data
     */
    public static final String THREAT_INTEL_DATA_INDEX_NAME_PREFIX = "opensearch-sap-threatintel";

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
     * Additional fields for datasource
     */
    private static final ParseField STATE_FIELD = new ParseField("state");
    private static final ParseField CURRENT_INDEX_FIELD = new ParseField("current_index");
    private static final ParseField INDICES_FIELD = new ParseField("indices");
    private static final ParseField DATABASE_FIELD = new ParseField("database");
    private static final ParseField UPDATE_STATS_FIELD = new ParseField("update_stats");
    private static final ParseField TASK_FIELD = new ParseField("task");


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
     * Additional variables for datasource
     */

    /**
     * @param state State of a datasource
     * @return State of a datasource
     */
    private DatasourceState state;

    /**
     * @param currentIndex the current index name having threat intel feed data
     * @return the current index name having threat intel feed data
     */
    private String currentIndex;

    /**
     * @param indices A list of indices having threat intel feed data including currentIndex
     * @return A list of indices having threat intel feed data including currentIndex
     */
    private List<String> indices;

    /**
     * @param database threat intel feed database information
     * @return threat intel feed database information
     */
    private Database database;

    /**
     * @param updateStats threat intel feed database update statistics
     * @return threat intel feed database update statistics
     */
    private UpdateStats updateStats;

    /**
     * @param task Task that {@link DatasourceRunner} will execute
     * @return Task that {@link DatasourceRunner} will execute
     */
    private DatasourceTask task;

    /**
     * Datasource parser
     */
    public static final ConstructingObjectParser<Datasource, Void> PARSER = new ConstructingObjectParser<>(
            "datasource_metadata",
            true,
            args -> {
                String name = (String) args[0];
                Instant lastUpdateTime = Instant.ofEpochMilli((long) args[1]);
                Instant enabledTime = args[2] == null ? null : Instant.ofEpochMilli((long) args[2]);
                boolean isEnabled = (boolean) args[3];
                IntervalSchedule schedule = (IntervalSchedule) args[4];
                DatasourceTask task = DatasourceTask.valueOf((String) args[5]);
                DatasourceState state = DatasourceState.valueOf((String) args[6]);
                String currentIndex = (String) args[7];
                List<String> indices = (List<String>) args[8];
                Database database = (Database) args[9];
                UpdateStats updateStats = (UpdateStats) args[10];
                Datasource parameter = new Datasource(
                    name,
                    lastUpdateTime,
                    enabledTime,
                    isEnabled,
                    schedule,
                    task,
                    state,
                    currentIndex,
                    indices,
                    database,
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
        PARSER.declareString(ConstructingObjectParser.constructorArg(), TASK_FIELD);
        PARSER.declareString(ConstructingObjectParser.constructorArg(), STATE_FIELD);
        PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), CURRENT_INDEX_FIELD);
        PARSER.declareStringArray(ConstructingObjectParser.constructorArg(), INDICES_FIELD);
        PARSER.declareObject(ConstructingObjectParser.constructorArg(), Database.PARSER, DATABASE_FIELD);
        PARSER.declareObject(ConstructingObjectParser.constructorArg(), UpdateStats.PARSER, UPDATE_STATS_FIELD);
    }

    public Datasource() {
        this(null, null);
    }

    public Datasource(final String name, final Instant lastUpdateTime, final Instant enabledTime, final Boolean isEnabled,
                      final IntervalSchedule schedule, DatasourceTask task, final DatasourceState state, final String currentIndex,
                      final List<String> indices, final Database database, final UpdateStats updateStats) {
        this.name = name;
        this.lastUpdateTime = lastUpdateTime;
        this.enabledTime = enabledTime;
        this.isEnabled = isEnabled;
        this.schedule = schedule;
        this.task = task;
        this.state = state;
        this.currentIndex = currentIndex;
        this.indices = indices;
        this.database = database;
        this.updateStats = updateStats;
    }

    public Datasource(final String name, final IntervalSchedule schedule) {
        this(
                name,
                Instant.now().truncatedTo(ChronoUnit.MILLIS),
                null,
                false,
                schedule,
                DatasourceTask.ALL,
                DatasourceState.CREATING,
                null,
                new ArrayList<>(),
                new Database(),
                new UpdateStats()
        );
    }

    public Datasource(final StreamInput in) throws IOException {
        name = in.readString();
        lastUpdateTime = toInstant(in.readVLong());
        enabledTime = toInstant(in.readOptionalVLong());
        isEnabled = in.readBoolean();
        schedule = new IntervalSchedule(in);
        task = DatasourceTask.valueOf(in.readString());
        state = DatasourceState.valueOf(in.readString());
        currentIndex = in.readOptionalString();
        indices = in.readStringList();
        database = new Database(in);
        updateStats = new UpdateStats(in);
    }

    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeVLong(lastUpdateTime.toEpochMilli());
        out.writeOptionalVLong(enabledTime == null ? null : enabledTime.toEpochMilli());
        out.writeBoolean(isEnabled);
        schedule.writeTo(out);
        out.writeString(task.name());
        out.writeString(state.name());
        out.writeOptionalString(currentIndex);
        out.writeStringCollection(indices);
        database.writeTo(out);
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
        builder.field(TASK_FIELD.getPreferredName(), task.name());
        builder.field(STATE_FIELD.getPreferredName(), state.name());
        if (currentIndex != null) {
            builder.field(CURRENT_INDEX_FIELD.getPreferredName(), currentIndex);
        }
        builder.field(INDICES_FIELD.getPreferredName(), indices);
        builder.field(DATABASE_FIELD.getPreferredName(), database);
        builder.field(UPDATE_STATS_FIELD.getPreferredName(), updateStats);
        builder.endObject();
        return builder;
    }

    // getters and setters
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

    public DatasourceTask getTask() {
        return task;
    }
    public void setLastUpdateTime(Instant lastUpdateTime) {
        this.lastUpdateTime = lastUpdateTime;
    }
    public void setCurrentIndex(String currentIndex) {
        this.currentIndex = currentIndex;
    }

    public void setTask(DatasourceTask task) {
        this.task = task;
    }
    @Override
    public Long getLockDurationSeconds() {
        return ThreatIntelLockService.LOCK_DURATION_IN_SECONDS;
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

    /**
     * Reset database so that it can be updated in next run regardless there is new update or not
     */
    public void resetDatabase() {
        database.setFeedId(null);
        database.setFeedName(null);
        database.setFeedFormat(null);
        database.setEndpoint(null);
        database.setDescription(null);
        database.setOrganization(null);
        database.setContained_iocs_field(null);
        database.setIocCol(null);
        database.setFeedFormat(null);
    }

    /**
     * Index name for a datasource with given suffix
     *
     * @param suffix the suffix of a index name
     * @return index name for a datasource with given suffix
     */
    public String newIndexName(final String suffix) {
        return String.format(Locale.ROOT, "%s.%s.%s", THREAT_INTEL_DATA_INDEX_NAME_PREFIX, name, suffix);
    }

    /**
     * Set database attributes with given input
     *
     * @param datasourceManifest the datasource manifest
     * @param fields the fields
     */
    public void setDatabase(final DatasourceManifest datasourceManifest, final List<String> fields) {
        this.database.feedId = datasourceManifest.getFeedId();
        this.database.feedName = datasourceManifest.getName();
        this.database.feedFormat = datasourceManifest.getFeedType();
        this.database.endpoint = datasourceManifest.getUrl();
        this.database.organization = datasourceManifest.getOrganization();
        this.database.description = datasourceManifest.getDescription();
        this.database.contained_iocs_field = datasourceManifest.getContainedIocs();
        this.database.iocCol = datasourceManifest.getIocCol();
        this.database.fields = fields;
    }

    /**
     * Checks if the database fields are compatible with the given set of fields.
     *
     * If database fields are null, it is compatible with any input fields
     * as it hasn't been generated before.
     *
     * @param fields The set of input fields to check for compatibility.
     * @return true if the database fields are compatible with the given input fields, false otherwise.
     */
    public boolean isCompatible(final List<String> fields) {
        if (database.fields == null) {
            return true;
        }

        if (fields.size() < database.fields.size()) {
            return false;
        }

        Set<String> fieldsSet = new HashSet<>(fields);
        for (String field : database.fields) {
            if (fieldsSet.contains(field) == false) {
                return false;
            }
        }
        return true;
    }

    public DatasourceState getState() {
        return state;
    }

    public List<String> getIndices() {
        return indices;
    }

    public void setState(DatasourceState previousState) {
        this.state = previousState;
    }

    public Database getDatabase() {
        return this.database;
    }

    public UpdateStats getUpdateStats() {
        return this.updateStats;
    }

    /**
     * Database of a datasource
     */
    public static class Database implements Writeable, ToXContent {
        private static final ParseField FEED_ID = new ParseField("feed_id");
        private static final ParseField FEED_NAME = new ParseField("feed_name");
        private static final ParseField FEED_FORMAT = new ParseField("feed_format");
        private static final ParseField ENDPOINT_FIELD = new ParseField("endpoint");
        private static final ParseField DESCRIPTION = new ParseField("description");
        private static final ParseField ORGANIZATION = new ParseField("organization");
        private static final ParseField CONTAINED_IOCS_FIELD = new ParseField("contained_iocs_field");
        private static final ParseField IOC_COL = new ParseField("ioc_col");
        private static final ParseField FIELDS_FIELD = new ParseField("fields");

        /**
         * @param feedId id of the feed
         * @return id of the feed
         */
        private String feedId;

        /**
         * @param feedFormat format of the feed (csv, json...)
         * @return the type of feed ingested
         */
        private String feedFormat;

        /**
         * @param endpoint URL of a manifest file
         * @return URL of a manifest file
         */
        private String endpoint;

        /**
         * @param feedName name of the threat intel feed
         * @return name of the threat intel feed
         */
        private String feedName;

        /**
         * @param description description of the threat intel feed
         * @return description of the threat intel feed
         */
        private String description;

        /**
         * @param organization organization of the threat intel feed
         * @return organization of the threat intel feed
         */
        private String organization;

        /**
         * @param contained_iocs_field list of iocs contained in a given feed
         * @return list of iocs contained in a given feed
         */
        private List<String> contained_iocs_field;

        /**
         * @param ioc_col column of the contained ioc
         * @return column of the contained ioc
         */
        private String iocCol;

        /**
         * @param fields A list of available fields in the database
         * @return A list of available fields in the database
         */
        private List<String> fields;

        public Database(String feedId, String feedName, String feedFormat, final String endpoint, final String description,
                        final String organization, final List<String> contained_iocs_field, final String iocCol, final List<String> fields) {
            this.feedId = feedId;
            this.feedName = feedName;
            this.feedFormat = feedFormat;
            this.endpoint = endpoint;
            this.description = description;
            this.organization = organization;
            this.contained_iocs_field = contained_iocs_field;
            this.iocCol = iocCol;
            this.fields = fields;
        }

        private static final ConstructingObjectParser<Database, Void> PARSER = new ConstructingObjectParser<>(
                "datasource_metadata_database",
                true,
                args -> {
                    String feedId = (String) args[0];
                    String feedName = (String) args[1];
                    String feedFormat = (String) args[2];
                    String endpoint = (String) args[3];
                    String description = (String) args[4];
                    String organization = (String) args[5];
                    List<String> contained_iocs_field = (List<String>) args[6];
                    String iocCol = (String) args[7];
                    List<String> fields = (List<String>) args[8];
                    return new Database(feedFormat, endpoint, feedId, feedName, description, organization, contained_iocs_field, iocCol, fields);
                }
        );
        static {
            PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), FEED_ID);
            PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), FEED_NAME);
            PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), FEED_FORMAT);
            PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), ENDPOINT_FIELD);
            PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), DESCRIPTION);
            PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), ORGANIZATION);
            PARSER.declareStringArray(ConstructingObjectParser.constructorArg(), CONTAINED_IOCS_FIELD);
            PARSER.declareString(ConstructingObjectParser.optionalConstructorArg(), IOC_COL);
            PARSER.declareStringArray(ConstructingObjectParser.optionalConstructorArg(), FIELDS_FIELD);
        }

        public Database(final StreamInput in) throws IOException {
            feedId = in.readString();
            feedName = in.readString();
            feedFormat = in.readString();
            endpoint = in.readString();
            description = in.readString();
            organization = in.readString();
            contained_iocs_field = in.readStringList();
            iocCol = in.readString();
            fields = in.readOptionalStringList();
        }

        private Database(){}

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            out.writeString(feedId);
            out.writeString(feedName);
            out.writeString(feedFormat);
            out.writeString(endpoint);
            out.writeString(description);
            out.writeString(organization);
            out.writeStringCollection(contained_iocs_field);
            out.writeString(iocCol);
            out.writeOptionalStringCollection(fields);
        }

        @Override
        public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
            builder.startObject();
            builder.field(FEED_ID.getPreferredName(), feedId);
            builder.field(FEED_NAME.getPreferredName(), feedName);
            builder.field(FEED_FORMAT.getPreferredName(), feedFormat);
            builder.field(ENDPOINT_FIELD.getPreferredName(), endpoint);
            builder.field(DESCRIPTION.getPreferredName(), description);
            builder.field(ORGANIZATION.getPreferredName(), organization);
            builder.field(CONTAINED_IOCS_FIELD.getPreferredName(), contained_iocs_field);
            builder.field(IOC_COL.getPreferredName(), iocCol);

//            if (provider != null) {
//                builder.field(PROVIDER_FIELD.getPreferredName(), provider);
//            }
//            if (updatedAt != null) {
//                builder.timeField(
//                        UPDATED_AT_FIELD.getPreferredName(),
//                        UPDATED_AT_FIELD_READABLE.getPreferredName(),
//                        updatedAt.toEpochMilli()
//                );
//            }
            if (fields != null) {
                builder.startArray(FIELDS_FIELD.getPreferredName());
                for (String field : fields) {
                    builder.value(field);
                }
                builder.endArray();
            }
            builder.endObject();
            return builder;
        }

        public String getEndpoint() {
            return this.endpoint;
        }

        public List<String> getFields() {
            return fields;
        }
        public void setFeedId(String feedId) {
            this.feedId = feedId;
        }

        public void setFeedFormat(String feedFormat) {
            this.feedFormat = feedFormat;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }

        public void setFeedName(String feedName) {
            this.feedName = feedName;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public void setOrganization(String organization) {
            this.organization = organization;
        }

        public void setContained_iocs_field(List<String> contained_iocs_field) {
            this.contained_iocs_field = contained_iocs_field;
        }

        public void setIocCol(String iocCol) {
            this.iocCol = iocCol;
        }

        public void setFields(List<String> fields) {
            this.fields = fields;
        }

    }

    /**
     * Update stats of a datasource
     */
    public static class UpdateStats implements Writeable, ToXContent {
        private static final ParseField LAST_SUCCEEDED_AT_FIELD = new ParseField("last_succeeded_at_in_epoch_millis");
        private static final ParseField LAST_SUCCEEDED_AT_FIELD_READABLE = new ParseField("last_succeeded_at");
        private static final ParseField LAST_PROCESSING_TIME_IN_MILLIS_FIELD = new ParseField("last_processing_time_in_millis");
        private static final ParseField LAST_FAILED_AT_FIELD = new ParseField("last_failed_at_in_epoch_millis");
        private static final ParseField LAST_FAILED_AT_FIELD_READABLE = new ParseField("last_failed_at");
        private static final ParseField LAST_SKIPPED_AT = new ParseField("last_skipped_at_in_epoch_millis");
        private static final ParseField LAST_SKIPPED_AT_READABLE = new ParseField("last_skipped_at");

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
                "datasource_metadata_update_stats",
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

//    /**
//     * Builder class for Datasource
//     */
//    public static class Builder {
//        public static Datasource build(final PutDatasourceRequest request) {
//            String id = request.getName();
//            IntervalSchedule schedule = new IntervalSchedule(
//                    Instant.now().truncatedTo(ChronoUnit.MILLIS),
//                    (int) request.getUpdateInterval().days(),
//                    ChronoUnit.DAYS
//            );
//            String feedFormat = request.getFeedFormat();
//            String endpoint = request.getEndpoint();
//            String feedName = request.getFeedName();
//            String description = request.getDescription();
//            String organization = request.getOrganization();
//            List<String> contained_iocs_field = request.getContained_iocs_field();
//            return new Datasource(id, schedule, feedFormat, endpoint, feedName, description, organization, contained_iocs_field);
//        }
//    }
}