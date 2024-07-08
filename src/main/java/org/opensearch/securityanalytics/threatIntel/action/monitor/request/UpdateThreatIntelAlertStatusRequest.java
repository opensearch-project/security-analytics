package org.opensearch.securityanalytics.threatIntel.action.monitor.request;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.List;

public class UpdateThreatIntelAlertStatusRequest extends ActionRequest {
    public static final String ALERT_IDS_FIELD = "alert_ids";
    public static final String STATE_FIELD = "state";
    private final List<String> alertIds;
    private final Alert.State state;
    private final String monitorId;

    public UpdateThreatIntelAlertStatusRequest(StreamInput sin) throws IOException {
        alertIds = sin.readStringList();
        state = sin.readEnum(Alert.State.class);
        monitorId = sin.readOptionalString();
    }

    public UpdateThreatIntelAlertStatusRequest(List<String> alertIds, Alert.State state) {
        this.alertIds = alertIds;
        this.state = state;
        monitorId = null;
    }

    public UpdateThreatIntelAlertStatusRequest(List<String> alertIds, String monitorId, Alert.State state) {
        this.alertIds = alertIds;
        this.state = state;
        this.monitorId = monitorId;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeStringCollection(alertIds);
        out.writeEnum(state);
        out.writeOptionalString(monitorId);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException actionRequestValidationException = null;

        if (state == null) {
            actionRequestValidationException = new ActionRequestValidationException();
            actionRequestValidationException.addValidationError("State cannot be null");
        }
        if (alertIds == null || alertIds.isEmpty()) {
            actionRequestValidationException = new ActionRequestValidationException();
            actionRequestValidationException.addValidationError("At least one alert id is required");
        }
        if (false == (state.equals(Alert.State.ACKNOWLEDGED) || state.equals(Alert.State.COMPLETED))) {
            actionRequestValidationException = new ActionRequestValidationException();
            actionRequestValidationException.addValidationError(String.format("%s is not a supported state for alert status update." +
                    " Only COMPLETED and ACKNOWLEDGED states allowed", state.toString()));
        }
        return actionRequestValidationException;
    }

    public List<String> getAlertIds() {
        return alertIds;
    }

    public Alert.State getState() {
        return state;
    }

    public String getMonitorId() {
        return monitorId;
    }
}
