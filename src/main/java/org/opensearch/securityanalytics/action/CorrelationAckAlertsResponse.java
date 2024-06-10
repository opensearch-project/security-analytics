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

public class CorrelationAckAlertsResponse  extends ActionResponse implements ToXContentObject {

    private final List<CorrelationAlert> acknowledged;
    private final List<CorrelationAlert> failed;

    public CorrelationAckAlertsResponse(List<CorrelationAlert> acknowledged, List<CorrelationAlert> failed) {
        this.acknowledged = acknowledged;
        this.failed = failed;
    }

    public CorrelationAckAlertsResponse(StreamInput sin) throws IOException {
        this(
                Collections.unmodifiableList(sin.readList(CorrelationAlert::new)),
                Collections.unmodifiableList(sin.readList(CorrelationAlert::new))
        );
    }

    @Override
    public void writeTo(StreamOutput streamOutput) throws IOException {
        streamOutput.writeList(this.acknowledged);
        streamOutput.writeList(this.failed);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field("acknowledged",this.acknowledged)
                .field("failed",this.failed);
        return builder.endObject();
    }

    public List<CorrelationAlert> getAcknowledged() {
        return acknowledged;
    }

    public List<CorrelationAlert> getFailed() {
        return failed;
    }
}
