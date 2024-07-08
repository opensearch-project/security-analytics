package org.opensearch.securityanalytics.threatIntel.action.monitor.request;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

public class DeleteThreatIntelMonitorRequest extends ActionRequest {

    private String monitorId;

    public DeleteThreatIntelMonitorRequest(String monitorId) {
        super();
        this.monitorId = monitorId;
    }

    public DeleteThreatIntelMonitorRequest(StreamInput sin) throws IOException {
        this(sin.readString());
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(monitorId);
    }

    public String getMonitorId() {
        return monitorId;
    }

}
