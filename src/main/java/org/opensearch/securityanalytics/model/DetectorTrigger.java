/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.ParseField;
import org.opensearch.common.UUIDs;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.script.Script;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public class DetectorTrigger implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private String id;

    private String name;

    private List<String> ruleTypes;

    private List<String> ruleSeverityLevels;

    private List<String> tags;

    private List<Action> actions;

    private static final String ID_FIELD = "id";
    private static final String RULE_TYPES_FIELD = "types";
    private static final String RULE_SEV_LEVELS_FIELD = "sev_levels";
    private static final String RULE_TAGS_FIELD = "tags";
    private static final String ACTIONS_FIELD = "actions";

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY = new NamedXContentRegistry.Entry(
            DetectorTrigger.class,
            new ParseField(ID_FIELD),
            DetectorTrigger::parse
    );

    public DetectorTrigger(String id, String name, List<String> ruleTypes, List<String> ruleSeverityLevels, List<String> tags, List<Action> actions) {
        this.id = id == null? UUIDs.base64UUID(): id;
        this.name = name;
        this.ruleTypes = ruleTypes;
        this.ruleSeverityLevels = ruleSeverityLevels;
        this.tags = tags;
        this.actions = actions;
    }

    public DetectorTrigger(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readStringList(),
                sin.readStringList(),
                sin.readStringList(),
                sin.readList(Action::readFrom)
        );
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(
                RULE_TYPES_FIELD, ruleTypes,
                RULE_SEV_LEVELS_FIELD, ruleSeverityLevels,
                RULE_TAGS_FIELD, tags,
                ACTIONS_FIELD, actions.stream().map(Action::asTemplateArg)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeString(name);
        out.writeStringCollection(ruleTypes);
        out.writeStringCollection(ruleSeverityLevels);
        out.writeStringCollection(tags);
        out.writeCollection(actions);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        String[] ruleTypeArray = new String[]{};
        ruleTypeArray = ruleTypes.toArray(ruleTypeArray);

        String[] ruleSevLevelArray = new String[]{};
        ruleSevLevelArray = ruleSeverityLevels.toArray(ruleSevLevelArray);

        String[] tagArray = new String[]{};
        tagArray = tags.toArray(tagArray);

        Action[] actionArray = new Action[]{};
        actionArray = actions.toArray(actionArray);

        return builder.startObject()
                .field(ID_FIELD, id)
                .field(Detector.NAME_FIELD, name)
                .field(RULE_TYPES_FIELD, ruleTypeArray)
                .field(RULE_SEV_LEVELS_FIELD, ruleSevLevelArray)
                .field(RULE_TAGS_FIELD, tagArray)
                .field(ACTIONS_FIELD, actionArray)
                .endObject();
    }

    public static DetectorTrigger parse(XContentParser xcp) throws IOException {
        String id = null;
        String name = null;
        List<String> ruleTypes = new ArrayList<>();
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
                case RULE_TYPES_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String ruleType = xcp.text();
                        ruleTypes.add(ruleType);
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

        return new DetectorTrigger(id, name, ruleTypes, ruleSeverityLevels, tags, actions);
    }

    public static DetectorTrigger readFrom(StreamInput sin) throws IOException {
        return new DetectorTrigger(sin);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DetectorTrigger that = (DetectorTrigger) o;
        return Objects.equals(id, that.id) && Objects.equals(name, that.name) && Objects.equals(ruleTypes, that.ruleTypes) && Objects.equals(ruleSeverityLevels, that.ruleSeverityLevels) && Objects.equals(tags, that.tags) && Objects.equals(actions, that.actions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, ruleTypes, ruleSeverityLevels, tags, actions);
    }

    public Script convertToCondition() {
        StringBuilder condition = new StringBuilder();

        StringBuilder ruleTypeBuilder = new StringBuilder();
        int size = ruleTypes.size();
        for (int idx = 0; idx < size; ++idx) {
            ruleTypeBuilder.append(String.format(Locale.getDefault(), "query[tag=%s]", ruleTypes.get(idx)));
            if (idx < size - 1) {
                ruleTypeBuilder.append(" || ");
            }
        }
        condition.append("(").append(ruleTypeBuilder).append(")");

        StringBuilder ruleSevLevelBuilder = new StringBuilder();
        size = ruleSeverityLevels.size();
        for (int idx = 0; idx < size; ++idx) {
            ruleSevLevelBuilder.append(String.format(Locale.getDefault(), "query[tag=%s]", ruleSeverityLevels.get(idx)));
            if (idx < size - 1) {
                ruleSevLevelBuilder.append(" || ");
            }
        }

        if (size > 0) {
            condition.append(" && ").append("(").append(ruleSevLevelBuilder).append(")");
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
            condition.append(" && ").append("(").append(tagBuilder).append(")");
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
        return !ruleSeverityLevels.isEmpty()? ruleSeverityLevels.get(0): "low";
    }

    public List<Action> getActions() {
        return actions;
    }
}