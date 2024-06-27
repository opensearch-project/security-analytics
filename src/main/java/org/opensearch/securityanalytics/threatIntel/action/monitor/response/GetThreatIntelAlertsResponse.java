package org.opensearch.securityanalytics.threatIntel.action.monitor.response;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelAlertDto;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class GetThreatIntelAlertsResponse extends ActionResponse implements ToXContentObject {

    private static final String ALERTS_FIELD = "alerts";
    private static final String TOTAL_ALERTS_FIELD = "total_alerts";

    private List<ThreatIntelAlertDto> alerts;
    private Integer totalAlerts;

    public GetThreatIntelAlertsResponse(List<ThreatIntelAlertDto> alerts, Integer totalAlerts) {
        super();
        this.alerts = alerts;
        this.totalAlerts = totalAlerts;
    }

    public GetThreatIntelAlertsResponse(StreamInput sin) throws IOException {
        this(
                Collections.unmodifiableList(sin.readList(ThreatIntelAlertDto::new)),
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

    public List<ThreatIntelAlertDto> getAlerts() {
        return this.alerts;
    }

    public Integer getTotalAlerts() {
        return this.totalAlerts;
    }
}

