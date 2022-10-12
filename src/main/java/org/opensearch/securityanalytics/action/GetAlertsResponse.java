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
import org.opensearch.securityanalytics.model.Detector;

public class GetAlertsResponse extends ActionResponse implements ToXContentObject {

    private List<AlertDto> alerts;
    private Integer totalAlerts;
    private String detectorType;

    public GetAlertsResponse(List<AlertDto> alerts, Integer totalAlerts, String detectorType) {
        super();
        this.alerts = alerts;
        this.totalAlerts = totalAlerts;
        this.detectorType = detectorType;
    }

    public GetAlertsResponse(StreamInput sin) throws IOException {
        this(
            Collections.unmodifiableList(sin.readList(AlertDto::new)),
            sin.readInt(),
            sin.readString()
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(this.alerts);
        out.writeInt(this.totalAlerts);
        out.writeString(this.detectorType);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field("alerts", alerts)
                .field("total_findings", totalAlerts)
                .field("detectorType", detectorType);
        return builder.endObject();
    }

    public List<AlertDto> getAlerts() {
        return this.alerts;
    }

    public Integer getTotalAlerts() {
        return this.totalAlerts;
    }

    public String getDetectorType() {
        return detectorType;
    }
}