/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.opensearch.common.ParseField;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class DetectorInput implements Writeable, ToXContentObject {

    private String description;

    private List<String> indices;

    private List<DetectorRule> rules;

    private static final String NO_DESCRIPTION = "";

    protected static final String DESCRIPTION_FIELD = "description";
    protected static final String INDICES_FIELD = "indices";
    private static final String DETECTOR_INPUT_FIELD = "detector_input";
    protected static final String RULES_FIELD = "rules";

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY = new NamedXContentRegistry.Entry(
            DetectorInput.class,
            new ParseField(DETECTOR_INPUT_FIELD),
            DetectorInput::parse
    );

    public DetectorInput(String description, List<String> indices, List<DetectorRule> rules) {
        this.description = description;
        this.indices = indices;
        this.rules = rules;
    }

    public DetectorInput(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readStringList(),
                sin.readList(DetectorRule::new)
        );
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(
                DESCRIPTION_FIELD, description,
                INDICES_FIELD, indices,
                RULES_FIELD, rules.stream().map(DetectorRule::asTemplateArg).collect(Collectors.toList())
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(description);
        out.writeStringCollection(indices);
        out.writeCollection(rules);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        String[] indicesArray = new String[]{};
        indicesArray = indices.toArray(indicesArray);

        DetectorRule[] rulesArray = new DetectorRule[]{};
        rulesArray = rules.toArray(rulesArray);

        builder.startObject()
                .startObject(DETECTOR_INPUT_FIELD)
                .field(DESCRIPTION_FIELD, description)
                .field(INDICES_FIELD, indicesArray)
                .field(RULES_FIELD, rulesArray)
                .endObject()
                .endObject();
        return builder;
    }

    public static DetectorInput parse(XContentParser xcp) throws IOException {
        String description = NO_DESCRIPTION;
        List<String> indices = new ArrayList<>();
        List<DetectorRule> rules = new ArrayList<>();

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
                case RULES_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        rules.add(DetectorRule.parse(xcp));
                    }
            }
        }
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.END_OBJECT, xcp.nextToken(), xcp);
        return new DetectorInput(description, indices, rules);
    }

    public static DetectorInput readFrom(StreamInput sin) throws IOException {
        return new DetectorInput(sin);
    }

    public void setRules(List<DetectorRule> rules) {
        this.rules = rules;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getIndices() {
        return indices;
    }

    public List<DetectorRule> getRules() {
        return rules;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DetectorInput input = (DetectorInput) o;
        return Objects.equals(description, input.description) && Objects.equals(indices, input.indices) && Objects.equals(rules, input.rules);
    }

    @Override
    public int hashCode() {
        return Objects.hash(description, indices, rules);
    }
}