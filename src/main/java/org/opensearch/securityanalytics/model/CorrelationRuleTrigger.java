/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.UUIDs;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.script.Script;
import org.opensearch.script.ScriptType;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class CorrelationRuleTrigger implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private String id;

    private String name;

    private String severity;

    private List<Action> actions;

    private static final String ID_FIELD = "id";

    private static final String SEVERITY_FIELD = "severity";
    private static final String ACTIONS_FIELD = "actions";

    private static final String NAME_FIELD = "name";

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY = new NamedXContentRegistry.Entry(
            CorrelationRuleTrigger.class,
            new ParseField(ID_FIELD),
            CorrelationRuleTrigger::parse
    );

    public CorrelationRuleTrigger(String id,
                           String name,
                           String severity,
                           List<Action> actions) {
        this.id = id == null ? UUIDs.base64UUID() : id;
        this.name = name;
        this.severity = severity;
        this.actions = actions;
    }

    public CorrelationRuleTrigger(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readList(Action::readFrom)
        );
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(
                ACTIONS_FIELD, actions.stream().map(Action::asTemplateArg)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeString(name);
        out.writeString(severity);
        out.writeCollection(actions);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {

        Action[] actionArray = new Action[]{};
        actionArray = actions.toArray(actionArray);

        return builder.startObject()
                .field(ID_FIELD, id)
                .field(NAME_FIELD, name)
                .field(SEVERITY_FIELD, severity)
                .field(ACTIONS_FIELD, actionArray)
                .endObject();
    }

    public static CorrelationRuleTrigger parse(XContentParser xcp) throws IOException {
        String id = null;
        String name = null;
        String severity = null;
        List<Action> actions = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case ID_FIELD:
                    id = xcp.text();
                    break;
                case NAME_FIELD:
                    name = xcp.text();
                    break;
                case SEVERITY_FIELD:
                    severity = xcp.text();
                    break;
                case ACTIONS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        Action action = Action.parse(xcp);
                        actions.add(action);
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new CorrelationRuleTrigger(id, name, severity, actions);
    }

    public static CorrelationRuleTrigger readFrom(StreamInput sin) throws IOException {
        return new CorrelationRuleTrigger(sin);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CorrelationRuleTrigger that = (CorrelationRuleTrigger) o;
        return Objects.equals(id, that.id) && Objects.equals(name, that.name) && Objects.equals(severity, that.severity)  && Objects.equals(actions, that.actions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, severity, actions);
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getSeverity() {
        return severity;
    }

    public List<Action> getActions() {
        List<Action> transformedActions = new ArrayList<>();

        if (actions != null) {
            for (Action action : actions) {
                String subjectTemplate = action.getSubjectTemplate() != null ? action.getSubjectTemplate().getIdOrCode() : "";
                subjectTemplate = subjectTemplate.replace("{{ctx.detector", "{{ctx.monitor");

                action.getMessageTemplate();
                String messageTemplate = action.getMessageTemplate().getIdOrCode();
                messageTemplate = messageTemplate.replace("{{ctx.detector", "{{ctx.monitor");

                Action transformedAction = new Action(action.getName(), action.getDestinationId(),
                        new Script(ScriptType.INLINE, Script.DEFAULT_TEMPLATE_LANG, subjectTemplate, Collections.emptyMap()),
                        new Script(ScriptType.INLINE, Script.DEFAULT_TEMPLATE_LANG, messageTemplate, Collections.emptyMap()),
                        action.getThrottleEnabled(), action.getThrottle(),
                        action.getId(), action.getActionExecutionPolicy());

                transformedActions.add(transformedAction);
            }
        }
        return transformedActions;
    }
}