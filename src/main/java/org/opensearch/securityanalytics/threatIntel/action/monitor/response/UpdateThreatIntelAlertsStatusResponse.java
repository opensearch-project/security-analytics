package org.opensearch.securityanalytics.threatIntel.action.monitor.response;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelAlertDto;

import java.io.IOException;
import java.util.List;

public class UpdateThreatIntelAlertsStatusResponse extends ActionResponse implements ToXContentObject {
    public static final String UPDATED_ALERTS = "updated_alerts";
    public static final String FAILURE_MESSAGES_FIELD = "failure_messages";
    private final List<ThreatIntelAlertDto> updatedAlerts;
    private final List<String> failureMessages;

    public UpdateThreatIntelAlertsStatusResponse(
            List<ThreatIntelAlertDto> updatedAlerts,
            List<String> failureMessages
    ) {
        this.updatedAlerts = updatedAlerts;
        this.failureMessages = failureMessages;
    }

    public UpdateThreatIntelAlertsStatusResponse(StreamInput sin) throws IOException {
        updatedAlerts = sin.readList(ThreatIntelAlertDto::new);
        failureMessages = sin.readStringList();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(updatedAlerts);
        out.writeStringCollection(failureMessages);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(UPDATED_ALERTS, updatedAlerts.toArray(new ThreatIntelAlertDto[0]))
                .field(FAILURE_MESSAGES_FIELD, failureMessages)
                .endObject();
    }
}
