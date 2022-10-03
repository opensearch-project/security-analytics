package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionResponse;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.commons.alerting.action.GetAlertsResponse;

import java.io.IOException;
import java.util.List;

public class GetDetectorAlertsResponse extends ActionResponse {

    private final String detectorId;

    private final List<AlertDto> alertsResponses;
    public GetDetectorAlertsResponse(String detectorId, List<GetAlertsResponse> alertsResponses) {
        this.detectorId = detectorId;
        this.alertsResponses = alertsResponses;
    }

    public GetDetectorAlertsResponse(StreamInput sin) throws IOException {
        detectorId = sin.readString();
        alertsResponses = sin.readList(GetAlertsResponse::new);
    }

    @Override
    public void writeTo(StreamOutput streamOutput) throws IOException {

    }
}
