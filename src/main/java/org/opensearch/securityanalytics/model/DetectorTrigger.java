/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.UUIDs;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.XContentParserUtils;
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

public class DetectorTrigger implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private String id;

    private String name;

    private String severity;

    private List<String> ruleTypes;

    private List<String> ruleIds;

    private List<String> ruleSeverityLevels;

    private List<String> tags;

    private List<Action> actions;

    private static final String ID_FIELD = "id";
    private static final String SEVERITY_FIELD = "severity";
    private static final String RULE_TYPES_FIELD = "types";
    private static final String RULE_IDS_FIELD = "ids";
    private static final String RULE_SEV_LEVELS_FIELD = "sev_levels";
    private static final String RULE_TAGS_FIELD = "tags";
    private static final String ACTIONS_FIELD = "actions";

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY = new NamedXContentRegistry.Entry(
            DetectorTrigger.class,
            new ParseField(ID_FIELD),
            DetectorTrigger::parse
    );

    public DetectorTrigger(String id, String name, String severity, List<String> ruleTypes, List<String> ruleIds, List<String> ruleSeverityLevels, List<String> tags, List<Action> actions) {
        this.id = id == null? UUIDs.base64UUID(): id;
        this.name = name;
        this.severity = severity;
        this.ruleTypes = ruleTypes.stream()
                .map( e -> e.toLowerCase(Locale.ROOT))
                .collect(Collectors.toList());
        this.ruleIds = ruleIds;
        this.ruleSeverityLevels = ruleSeverityLevels;
        this.tags = tags;
        this.actions = actions;
    }

    public DetectorTrigger(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readString(),
                sin.readStringList(),
                sin.readStringList(),
                sin.readStringList(),
                sin.readStringList(),
                sin.readList(Action::readFrom)
        );
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(
                RULE_TYPES_FIELD, ruleTypes,
                RULE_IDS_FIELD, ruleIds,
                RULE_SEV_LEVELS_FIELD, ruleSeverityLevels,
                RULE_TAGS_FIELD, tags,
                ACTIONS_FIELD, actions.stream().map(Action::asTemplateArg)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeString(name);
        out.writeString(severity);
        out.writeStringCollection(ruleTypes);
        out.writeStringCollection(ruleIds);
        out.writeStringCollection(ruleSeverityLevels);
        out.writeStringCollection(tags);
        out.writeCollection(actions);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        String[] ruleTypeArray = new String[]{};
        ruleTypeArray = ruleTypes.toArray(ruleTypeArray);

        String[] ruleNameArray = new String[]{};
        ruleNameArray = ruleIds.toArray(ruleNameArray);

        String[] ruleSevLevelArray = new String[]{};
        ruleSevLevelArray = ruleSeverityLevels.toArray(ruleSevLevelArray);

        String[] tagArray = new String[]{};
        tagArray = tags.toArray(tagArray);

        Action[] actionArray = new Action[]{};
        actionArray = actions.toArray(actionArray);

        return builder.startObject()
                .field(ID_FIELD, id)
                .field(Detector.NAME_FIELD, name)
                .field(SEVERITY_FIELD, severity)
                .field(RULE_TYPES_FIELD, ruleTypeArray)
                .field(RULE_IDS_FIELD, ruleNameArray)
                .field(RULE_SEV_LEVELS_FIELD, ruleSevLevelArray)
                .field(RULE_TAGS_FIELD, tagArray)
                .field(ACTIONS_FIELD, actionArray)
                .endObject();
    }

    public static DetectorTrigger parse(XContentParser xcp) throws IOException {
        String id = null;
        String name = null;
        String severity = null;
        List<String> ruleTypes = new ArrayList<>();
        List<String> ruleNames = new ArrayList<>();
        List<String> ruleSeverityLevels = new ArrayList<>();
        List<String> tags = new ArrayList<>();
        List<Action> actions = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case ID_FIELD:
                    id = xcp.text();
                    break;
                case Detector.NAME_FIELD:
                    name = xcp.text();
                    break;
                case SEVERITY_FIELD:
                    severity = xcp.text();
                    break;
                case RULE_TYPES_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String ruleType = xcp.text();
                        ruleTypes.add(ruleType);
                    }
                    break;
                case RULE_IDS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String ruleName = xcp.text();
                        ruleNames.add(ruleName);
                    }
                    break;
                case RULE_SEV_LEVELS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String ruleSeverityLevel = xcp.text();
                        ruleSeverityLevels.add(ruleSeverityLevel);
                    }
                    break;
                case RULE_TAGS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String tag = xcp.text();
                        tags.add(tag);
                    }
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

        return new DetectorTrigger(id, name, severity, ruleTypes, ruleNames, ruleSeverityLevels, tags, actions);
    }

    public static DetectorTrigger readFrom(StreamInput sin) throws IOException {
        return new DetectorTrigger(sin);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DetectorTrigger that = (DetectorTrigger) o;
        return Objects.equals(id, that.id) && Objects.equals(name, that.name) && Objects.equals(severity, that.severity) && Objects.equals(ruleTypes, that.ruleTypes) && Objects.equals(ruleIds, that.ruleIds) && Objects.equals(ruleSeverityLevels, that.ruleSeverityLevels) && Objects.equals(tags, that.tags) && Objects.equals(actions, that.actions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, severity, ruleTypes, ruleIds, ruleSeverityLevels, tags, actions);
    }

    public Script convertToCondition() {
        StringBuilder condition = new StringBuilder();
        boolean triggerFlag = false;

        StringBuilder ruleTypeBuilder = new StringBuilder();
        int size = ruleTypes.size();
        for (int idx = 0; idx < size; ++idx) {
            ruleTypeBuilder.append(String.format(Locale.getDefault(), "query[tag=%s]", ruleTypes.get(idx)));
            if (idx < size - 1) {
                ruleTypeBuilder.append(" || ");
            }
        }
        if (size > 0) {
            condition.append("(").append(ruleTypeBuilder).append(")");
            triggerFlag = true;
        }

        StringBuilder ruleNameBuilder = new StringBuilder();
        size = ruleIds.size();
        for (int idx = 0; idx < size; ++idx) {
            ruleNameBuilder.append(String.format(Locale.getDefault(), "query[name=%s]", ruleIds.get(idx)));
            if (idx < size - 1) {
                ruleNameBuilder.append(" || ");
            }
        }
        if (size > 0) {
            if (triggerFlag) {
                condition.append(" && ").append("(").append(ruleNameBuilder).append(")");
            } else {
                condition.append("(").append(ruleNameBuilder).append(")");
                triggerFlag = true;
            }
        }

        StringBuilder ruleSevLevelBuilder = new StringBuilder();
        size = ruleSeverityLevels.size();
        for (int idx = 0; idx < size; ++idx) {
            ruleSevLevelBuilder.append(String.format(Locale.getDefault(), "query[tag=%s]", ruleSeverityLevels.get(idx)));
            if (idx < size - 1) {
                ruleSevLevelBuilder.append(" || ");
            }
        }

        if (size > 0) {
            if (triggerFlag) {
                condition.append(" && ").append("(").append(ruleSevLevelBuilder).append(")");
            } else {
                condition.append("(").append(ruleSevLevelBuilder).append(")");
                triggerFlag = true;
            }
        }

        StringBuilder tagBuilder = new StringBuilder();
        size = tags.size();
        for (int idx = 0; idx < size; ++idx) {
            tagBuilder.append(String.format(Locale.getDefault(), "query[tag=%s]", tags.get(idx)));
            if (idx < size - 1) {
                ruleSevLevelBuilder.append(" || ");
            }
        }

        if (size > 0) {
            if (triggerFlag) {
                condition.append(" && ").append("(").append(tagBuilder).append(")");
            } else {
                condition.append("(").append(tagBuilder).append(")");
            }
        }

        return new Script(condition.toString());
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
            for (Action action: actions) {
                String subjectTemplate = action.getSubjectTemplate() != null ? action.getSubjectTemplate().getIdOrCode(): "";
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