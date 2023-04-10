/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.FindingWithDocs;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.model.Detector;

public class GetAlertsResponse extends ActionResponse implements ToXContentObject {

    private static final String ALERTS_FIELD = "alerts";
    private static final String TOTAL_ALERTS_FIELD = "total_alerts";

    private List<AlertDto> alerts;
    private Integer totalAlerts;

    public GetAlertsResponse(List<AlertDto> alerts, Integer totalAlerts) {
        super();
        this.alerts = alerts;
        this.totalAlerts = totalAlerts;
    }

    public GetAlertsResponse(StreamInput sin) throws IOException {
        this(
            Collections.unmodifiableList(sin.readList(AlertDto::new)),
            sin.readInt()
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(this.alerts);
        out.writeInt(this.totalAlerts);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(ALERTS_FIELD, alerts)
                .field(TOTAL_ALERTS_FIELD, totalAlerts);
        return builder.endObject();
    }

    public List<AlertDto> getAlerts() {
        return this.alerts;
    }

    public Integer getTotalAlerts() {
        return this.totalAlerts;
    }
}