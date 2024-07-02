package org.opensearch.securityanalytics.threatIntel.action.monitor.request;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.IndexTIFSourceConfigRequestInterface;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;

import java.io.IOException;

public class IndexThreatIntelMonitorRequest extends ActionRequest implements IndexTIFSourceConfigRequestInterface {

    public static final String THREAT_INTEL_MONITOR_ID = "threat_intel_monitor_id";

    private final String id;
    private final RestRequest.Method method;
    private final ThreatIntelMonitorDto monitor;

    public IndexThreatIntelMonitorRequest(String id, RestRequest.Method method, ThreatIntelMonitorDto monitor) {
        super();
        this.id = id;
        this.method = method;
        this.monitor = monitor;
    }

    public IndexThreatIntelMonitorRequest(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readEnum(RestRequest.Method.class), // method
                ThreatIntelMonitorDto.readFrom(sin)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeEnum(method);
        monitor.writeTo(out);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public String getId() {
        return id;
    }

    public RestRequest.Method getMethod() {
        return method;
    }

    public ThreatIntelMonitorDto getMonitor() {
        return monitor;
    }
}
