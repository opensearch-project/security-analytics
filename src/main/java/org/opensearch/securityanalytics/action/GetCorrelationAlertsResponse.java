package org.opensearch.securityanalytics.action;

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
                .field(CORRELATION_ALERTS_FIELD, alerts)
                .field(TOTAL_ALERTS_FIELD, totalAlerts);
        return builder.endObject();
    }

    public List<CorrelationAlert> getAlerts() {
        return this.alerts;
    }

    public Integer getTotalAlerts() {
        return this.totalAlerts;
    }
}