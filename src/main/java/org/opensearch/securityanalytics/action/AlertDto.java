package org.opensearch.securityanalytics.action;

import java.io.IOException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.commons.alerting.model.Alert;

public class AlertDto implements ToXContentObject, Writeable {

    String detectorId;

    Alert alert;

    public AlertDto(StreamInput sin) throws IOException {
        this(
            sin.readString(),
            new Alert(sin)
        );
    }

    public AlertDto(String detectorId, Alert alert) {
        this.detectorId = detectorId;
        this.alert = alert;
    }

    public static AlertDto readFrom(StreamInput sin) throws IOException {
        return new AlertDto(sin);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field("detectorId", detectorId)
                .field("alert", alert);
        return builder.endObject();
    }

    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(detectorId);
        alert.writeTo(out);
    }
}