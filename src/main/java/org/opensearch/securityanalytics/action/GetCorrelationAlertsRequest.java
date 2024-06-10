package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.time.Instant;
import java.util.Locale;

import static org.opensearch.action.ValidateActions.addValidationError;

public class GetCorrelationAlertsRequest extends ActionRequest {
    private String correlationRuleId;
    private String correlationRuleName;
    private Table table;
    private String severityLevel;
    private String alertState;

    private Instant startTime;

    private Instant endTime;

    public static final String CORRELATION_RULE_ID = "correlation_rule_id";

    public GetCorrelationAlertsRequest(
            String correlationRuleId,
            String correlationRuleName,
            Table table,
            String severityLevel,
            String alertState,
            Instant startTime,
            Instant endTime
    ) {
        super();
        this.correlationRuleId = correlationRuleId;
        this.correlationRuleName = correlationRuleName;
        this.table = table;
        this.severityLevel = severityLevel;
        this.alertState = alertState;
        this.startTime = startTime;
        this.endTime = endTime;
    }
    public GetCorrelationAlertsRequest(StreamInput sin) throws IOException {
        this(
                sin.readOptionalString(),
                sin.readOptionalString(),
                Table.readFrom(sin),
                sin.readString(),
                sin.readString(),
                sin.readOptionalInstant(),
                sin.readOptionalInstant()
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if ((correlationRuleId != null && correlationRuleId.isEmpty())) {
            validationException = addValidationError(String.format(Locale.getDefault(),
                            "Correlation ruleId is empty or not valid", CORRELATION_RULE_ID),
                    validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeOptionalString(correlationRuleId);
        out.writeOptionalString(correlationRuleName);
        table.writeTo(out);
        out.writeString(severityLevel);
        out.writeString(alertState);
        out.writeOptionalInstant(startTime);
        out.writeOptionalInstant(endTime);
    }

    public String getCorrelationRuleId() {
        return correlationRuleId;
    }

    public Table getTable() {
        return table;
    }

    public String getSeverityLevel() {
        return severityLevel;
    }

    public String getAlertState() {
        return alertState;
    }

    public String getCorrelationRuleName() {
        return correlationRuleName;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }
}

