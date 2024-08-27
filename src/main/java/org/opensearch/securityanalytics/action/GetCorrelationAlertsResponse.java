/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.commons.alerting.model.CorrelationAlert;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class GetCorrelationAlertsResponse  extends ActionResponse implements ToXContentObject {

    private static final Logger log = LogManager.getLogger(GetCorrelationAlertsResponse.class);
    private static final String CORRELATION_ALERTS_FIELD = "correlationAlerts";
    private static final String TOTAL_ALERTS_FIELD = "total_alerts";

    private List<CorrelationAlert> alerts;
    private Integer totalAlerts;

    public GetCorrelationAlertsResponse(List<CorrelationAlert> alerts, Integer totalAlerts) {
        super();
        this.alerts = alerts;
        this.totalAlerts = totalAlerts;
    }

    public GetCorrelationAlertsResponse(StreamInput sin) throws IOException {
        this(
                Collections.unmodifiableList(sin.readList(CorrelationAlert::new)),
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
                .field(CORRELATION_ALERTS_FIELD, this.alerts)
                .field(TOTAL_ALERTS_FIELD, this.totalAlerts);
        return builder.endObject();
    }
}