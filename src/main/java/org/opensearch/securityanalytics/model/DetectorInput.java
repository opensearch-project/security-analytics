/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.core.ParseField;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class DetectorInput implements Writeable, ToXContentObject {

    private String description;

    private List<String> indices;

    private List<DetectorRule> customRules;

    private List<DetectorRule> prePackagedRules;

    private static final String NO_DESCRIPTION = "";

    protected static final String DESCRIPTION_FIELD = "description";
    protected static final String INDICES_FIELD = "indices";
    private static final String DETECTOR_INPUT_FIELD = "detector_input";
    protected static final String CUSTOM_RULES_FIELD = "custom_rules";
    protected static final String PREPACKAGED_RULES_FIELD = "pre_packaged_rules";

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY = new NamedXContentRegistry.Entry(
            DetectorInput.class,
            new ParseField(DETECTOR_INPUT_FIELD),
            DetectorInput::parse
    );

    public DetectorInput(String description, List<String> indices, List<DetectorRule> customRules, List<DetectorRule> prePackagedRules) {
        this.description = description;
        this.indices = indices;
        this.customRules = customRules;
        this.prePackagedRules = prePackagedRules;
    }

    public DetectorInput(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readStringList(),
                sin.readList(DetectorRule::new),
                sin.readList(DetectorRule::new)
        );
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(
                DESCRIPTION_FIELD, description,
                INDICES_FIELD, indices,
                CUSTOM_RULES_FIELD, customRules.stream().map(DetectorRule::asTemplateArg).collect(Collectors.toList()),
                PREPACKAGED_RULES_FIELD, prePackagedRules.stream().map(DetectorRule::asTemplateArg).collect(Collectors.toList())
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(description);
        out.writeStringCollection(indices);
        out.writeCollection(customRules);
        out.writeCollection(prePackagedRules);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        String[] indicesArray = new String[]{};
        indicesArray = indices.toArray(indicesArray);

        DetectorRule[] customRulesArray = new DetectorRule[]{};
        customRulesArray = customRules.toArray(customRulesArray);

        DetectorRule[] prePackagedRulesArray = new DetectorRule[]{};
        prePackagedRulesArray = prePackagedRules.toArray(prePackagedRulesArray);

        builder.startObject()
                .startObject(DETECTOR_INPUT_FIELD)
                .field(DESCRIPTION_FIELD, description)
                .field(INDICES_FIELD, indicesArray)
                .field(CUSTOM_RULES_FIELD, customRulesArray)
                .field(PREPACKAGED_RULES_FIELD, prePackagedRulesArray)
                .endObject()
                .endObject();
        return builder;
    }

    public static DetectorInput parse(XContentParser xcp) throws IOException {
        String description = NO_DESCRIPTION;
        List<String> indices = new ArrayList<>();
        List<DetectorRule> customRules = new ArrayList<>();
        List<DetectorRule> prePackagedRules = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.FIELD_NAME, xcp.nextToken(), xcp);
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case DESCRIPTION_FIELD:
                    description = xcp.text();
                    break;
                case INDICES_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        indices.add(xcp.text());
                    }
                    break;
                case CUSTOM_RULES_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        customRules.add(DetectorRule.parse(xcp));
                    }
                    break;
                case PREPACKAGED_RULES_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        prePackagedRules.add(DetectorRule.parse(xcp));
                    }
            }
        }
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, xcp.nextToken(), xcp);
        return new DetectorInput(description, indices, customRules, prePackagedRules);
    }

    public static DetectorInput readFrom(StreamInput sin) throws IOException {
        return new DetectorInput(sin);
    }

    public void setCustomRules(List<DetectorRule> customRules) {
        this.customRules = customRules;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getIndices() {
        return indices;
    }

    public List<DetectorRule> getCustomRules() {
        return customRules;
    }

    public List<DetectorRule> getPrePackagedRules() {
        return prePackagedRules;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DetectorInput input = (DetectorInput) o;
        return Objects.equals(description, input.description) && Objects.equals(indices, input.indices) && Objects.equals(customRules, input.customRules) && Objects.equals(prePackagedRules, input.prePackagedRules);
    }

    @Override
    public int hashCode() {
        return Objects.hash(description, indices, customRules, prePackagedRules);
    }
}