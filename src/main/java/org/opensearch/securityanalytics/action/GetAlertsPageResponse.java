/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

/**
 * A page of alerts in cursor paging, see {@link GetAlertsPageRequest}: the alerts, the exact total of matching alerts
 * and the cursors of the next and previous pages (null when there is no next or previous page).
 */
public class GetAlertsPageResponse extends ActionResponse implements ToXContentObject {

    static final String ALERTS_FIELD = "alerts";
    static final String TOTAL_ALERTS_FIELD = "total_alerts";
    static final String NEXT_CURSOR_FIELD = "next_cursor";
    static final String PREV_CURSOR_FIELD = "prev_cursor";

    private final List<AlertDto> alerts;
    private final long totalAlerts;
    private final String nextCursor;
    private final String prevCursor;

    public GetAlertsPageResponse(List<AlertDto> alerts, long totalAlerts, String nextCursor, String prevCursor) {
        super();
        this.alerts = alerts;
        this.totalAlerts = totalAlerts;
        this.nextCursor = nextCursor;
        this.prevCursor = prevCursor;
    }

    public GetAlertsPageResponse(StreamInput sin) throws IOException {
        this(
                Collections.unmodifiableList(sin.readList(AlertDto::new)),
                sin.readVLong(),
                sin.readOptionalString(),
                sin.readOptionalString()
        );
    }

    /** An empty page, e.g. when there are no detectors */
    public static GetAlertsPageResponse empty() {
        return new GetAlertsPageResponse(List.of(), 0, null, null);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(alerts);
        out.writeVLong(totalAlerts);
        out.writeOptionalString(nextCursor);
        out.writeOptionalString(prevCursor);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(ALERTS_FIELD, alerts)
                .field(TOTAL_ALERTS_FIELD, totalAlerts)
                .field(NEXT_CURSOR_FIELD, nextCursor)
                .field(PREV_CURSOR_FIELD, prevCursor)
                .endObject();
    }

    public List<AlertDto> getAlerts() {
        return alerts;
    }

    public long getTotalAlerts() {
        return totalAlerts;
    }

    public String getNextCursor() {
        return nextCursor;
    }

    public String getPrevCursor() {
        return prevCursor;
    }
}
