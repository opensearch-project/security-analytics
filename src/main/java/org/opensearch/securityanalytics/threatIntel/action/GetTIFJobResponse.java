/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.core.ParseField;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

/**
 * threat intel tif job get request
 */
public class GetTIFJobResponse extends ActionResponse implements ToXContentObject {
    private static final ParseField FIELD_NAME_TIFJOBS = new ParseField("tifjobs");
    private static final ParseField FIELD_NAME_NAME = new ParseField("name");
    private static final ParseField FIELD_NAME_STATE = new ParseField("state");
    private static final ParseField FIELD_NAME_UPDATE_INTERVAL = new ParseField("update_interval_in_days");
    private static final ParseField FIELD_NAME_NEXT_UPDATE_AT = new ParseField("next_update_at_in_epoch_millis");
    private static final ParseField FIELD_NAME_NEXT_UPDATE_AT_READABLE = new ParseField("next_update_at");
    private static final ParseField FIELD_NAME_UPDATE_STATS = new ParseField("update_stats");
    private List<TIFJobParameter> tifJobParameters;

    /**
     * Default constructor
     *
     * @param tifJobParameters List of tifJobParameters
     */
    public GetTIFJobResponse(final List<TIFJobParameter> tifJobParameters) {
        this.tifJobParameters = tifJobParameters;
    }

    /**
     * Constructor with StreamInput
     *
     * @param in the stream input
     */
    public GetTIFJobResponse(final StreamInput in) throws IOException {
        tifJobParameters = in.readList(TIFJobParameter::new);
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeList(tifJobParameters);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject();
        builder.startArray(FIELD_NAME_TIFJOBS.getPreferredName());
        for (TIFJobParameter tifJobParameter : tifJobParameters) {
            builder.startObject();
            builder.field(FIELD_NAME_NAME.getPreferredName(), tifJobParameter.getName());
            builder.field(FIELD_NAME_STATE.getPreferredName(), tifJobParameter.getState());
            builder.field(FIELD_NAME_UPDATE_INTERVAL.getPreferredName(), tifJobParameter.getSchedule()); //TODO
            builder.timeField(
                FIELD_NAME_NEXT_UPDATE_AT.getPreferredName(),
                FIELD_NAME_NEXT_UPDATE_AT_READABLE.getPreferredName(),
                tifJobParameter.getSchedule().getNextExecutionTime(Instant.now()).toEpochMilli()
            );
            builder.field(FIELD_NAME_UPDATE_STATS.getPreferredName(), tifJobParameter.getUpdateStats());
            builder.endObject();
        }
        builder.endArray();
        builder.endObject();
        return builder;
    }
}
