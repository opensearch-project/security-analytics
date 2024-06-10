package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.ValidateActions;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class CorrelationAckAlertsRequest extends ActionRequest {
    private final List<String> correlationAlertIds;

    public CorrelationAckAlertsRequest(List<String> correlationAlertIds) {
        this.correlationAlertIds = correlationAlertIds;
    }

    public CorrelationAckAlertsRequest(StreamInput in) throws IOException {
        correlationAlertIds = Collections.unmodifiableList(in.readStringList());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if(correlationAlertIds == null || correlationAlertIds.isEmpty()) {
            validationException = ValidateActions.addValidationError("alert ids list cannot be empty", validationException);
        }
        return validationException;
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeStringCollection(this.correlationAlertIds);
    }

    public XContentBuilder toXContent(XContentBuilder builder, ToXContent.Params params) throws IOException {
        return builder.startObject()
                .field("correlation_alert_ids", correlationAlertIds)
                .endObject();
    }

    public static AckAlertsRequest readFrom(StreamInput sin) throws IOException {
        return new AckAlertsRequest(sin);
    }

    public List<String> getCorrelationAlertIds() {
        return correlationAlertIds;
    }
}
