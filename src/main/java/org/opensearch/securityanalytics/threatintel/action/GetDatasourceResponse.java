/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.action;

import org.opensearch.core.ParseField;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.threatintel.jobscheduler.Datasource;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

/**
 * threat intel datasource get request
 */
public class GetDatasourceResponse extends ActionResponse implements ToXContentObject {
    private static final ParseField FIELD_NAME_DATASOURCES = new ParseField("datasources");
    private static final ParseField FIELD_NAME_NAME = new ParseField("name");
    private static final ParseField FIELD_NAME_STATE = new ParseField("state");
    private static final ParseField FIELD_NAME_ENDPOINT = new ParseField("endpoint");
    private static final ParseField FIELD_NAME_UPDATE_INTERVAL = new ParseField("update_interval_in_days");
    private static final ParseField FIELD_NAME_NEXT_UPDATE_AT = new ParseField("next_update_at_in_epoch_millis");
    private static final ParseField FIELD_NAME_NEXT_UPDATE_AT_READABLE = new ParseField("next_update_at");
    private static final ParseField FIELD_NAME_DATABASE = new ParseField("database");
    private static final ParseField FIELD_NAME_UPDATE_STATS = new ParseField("update_stats");
    private List<Datasource> datasources;

    /**
     * Default constructor
     *
     * @param datasources List of datasources
     */
    public GetDatasourceResponse(final List<Datasource> datasources) {
        this.datasources = datasources;
    }

    /**
     * Constructor with StreamInput
     *
     * @param in the stream input
     */
    public GetDatasourceResponse(final StreamInput in) throws IOException {
        datasources = in.readList(Datasource::new);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeList(datasources);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject();
        builder.startArray(FIELD_NAME_DATASOURCES.getPreferredName());
        for (Datasource datasource : datasources) {
            builder.startObject();
            builder.field(FIELD_NAME_NAME.getPreferredName(), datasource.getName());
            builder.field(FIELD_NAME_STATE.getPreferredName(), datasource.getState());
            builder.field(FIELD_NAME_ENDPOINT.getPreferredName(), datasource.getEndpoint());
            builder.field(FIELD_NAME_UPDATE_INTERVAL.getPreferredName(), datasource.getSchedule()); //TODO
            builder.timeField(
                FIELD_NAME_NEXT_UPDATE_AT.getPreferredName(),
                FIELD_NAME_NEXT_UPDATE_AT_READABLE.getPreferredName(),
                datasource.getSchedule().getNextExecutionTime(Instant.now()).toEpochMilli()
            );
            builder.field(FIELD_NAME_DATABASE.getPreferredName(), datasource.getDatabase());
            builder.field(FIELD_NAME_UPDATE_STATS.getPreferredName(), datasource.getUpdateStats());
            builder.endObject();
        }
        builder.endArray();
        builder.endObject();
        return builder;
    }
}
