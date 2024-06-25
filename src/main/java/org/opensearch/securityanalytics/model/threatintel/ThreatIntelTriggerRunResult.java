package org.opensearch.securityanalytics.model.threatintel;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.commons.alerting.model.ActionRunResult;
import org.opensearch.commons.alerting.model.TriggerRunResult;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

//todo remove extension and implement as required
public class ThreatIntelTriggerRunResult extends TriggerRunResult {
    private static final Logger log = LogManager.getLogger(ThreatIntelTriggerRunResult.class);
    private List<String> triggeredDocs;
    private Map<String, Map<String, ActionRunResult>> actionResultsMap;

    public ThreatIntelTriggerRunResult(String triggerName, List<String> triggeredDocs, Exception error, Map<String, Map<String, ActionRunResult>> actionResultsMap) {
        super(triggerName, error);
        this.triggeredDocs = triggeredDocs;
        this.actionResultsMap = actionResultsMap;
    }

    public ThreatIntelTriggerRunResult(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readStringList(),
                sin.readException(),
                readActionResults(sin)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeStringCollection(getTriggeredDocs());
        out.writeInt(getActionResultsMap().size());
        for (Map.Entry<String, Map<String, ActionRunResult>> entry : getActionResultsMap().entrySet()) {
            out.writeString(entry.getKey());
            out.writeInt(entry.getValue().size());
            for (Map.Entry<String, ActionRunResult> actionEntry : entry.getValue().entrySet()) {
                out.writeString(actionEntry.getKey());
                actionEntry.getValue().writeTo(out);
            }
        }
    }

    public static TriggerRunResult readFrom(StreamInput sin) throws IOException {
        return new ThreatIntelTriggerRunResult(sin);
    }

    public static Map<String, Map<String, ActionRunResult>> readActionResults(StreamInput sin) throws IOException {
        Map<String, Map<String, ActionRunResult>> actionResultsMapReconstruct = new HashMap<>();
        int size = sin.readInt();
        for (int idx = 0; idx < size; idx++) {
            String alert = sin.readString();
            int actionResultsSize = sin.readInt();
            Map<String, ActionRunResult> actionRunResultElem = new HashMap<>();
            for (int i = 0; i < actionResultsSize; i++) {
                String actionId = sin.readString();
                ActionRunResult actionResult = ActionRunResult.readFrom(sin);
                actionRunResultElem.put(actionId, actionResult);
            }
            actionResultsMapReconstruct.put(alert, actionRunResultElem);
        }
        return actionResultsMapReconstruct;
    }

    public List<String> getTriggeredDocs() {
        return triggeredDocs;
    }

    public Map<String, Map<String, ActionRunResult>> getActionResultsMap() {
        return actionResultsMap;
    }

    @Override
    public XContentBuilder internalXContent(XContentBuilder builder, Params params) {
        try {
            return builder
                    .field("triggeredDocs", getTriggeredDocs())
                    .field("action_results", getActionResultsMap());
        } catch (IOException e) {
            log.error(String.format("Failed to serialize threat intel trigger run result %s", getTriggerName()), e);
            return builder;
        }
    }
}