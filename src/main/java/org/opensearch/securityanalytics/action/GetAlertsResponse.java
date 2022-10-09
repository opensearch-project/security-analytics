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
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.FindingWithDocs;
import org.opensearch.rest.RestStatus;

public class GetAlertsResponse extends ActionResponse implements ToXContentObject {

    private List<Alert> alerts;
    private Integer totalAlerts;
    private String detectorId;

    public GetAlertsResponse(List<Alert> alerts, Integer totalAlerts, String detectorId) {
        super();
        this.alerts = alerts;
        this.totalAlerts = totalAlerts;
        this.detectorId = detectorId;
    }

    public GetAlertsResponse(StreamInput sin) throws IOException {
        this(
            Collections.unmodifiableList(sin.readList(Alert::new)),
            sin.readInt(),
            sin.readString()
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(this.alerts);
        out.writeInt(this.totalAlerts);
        out.writeString(this.detectorId);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field("alerts", alerts)
                .field("total_findings", totalAlerts)
                .field("detectorId", detectorId);
        return builder.endObject();
    }

    public List<Alert> getAlerts() {
        return this.alerts;
    }

    public Integer getTotalAlerts() {
        return this.totalAlerts;
    }

    public String getDetectorId() {
        return detectorId;
    }
}