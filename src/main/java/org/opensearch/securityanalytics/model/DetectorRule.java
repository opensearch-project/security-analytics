/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

public class DetectorRule implements Writeable, ToXContentObject {

    private String id;

    private String name;

    private String rule;

    private List<String> tags;

    private static final List<String> INVALID_CHARACTERS = List.of(" ", "[", "]", "{", "}", "(", ")");

    protected static final String RULE_ID_FIELD = "id";
    protected static final String NAME_FIELD = "name";
    protected static final String RULE_FIELD = "rule";
    protected static final String TAGS_FIELD = "tags";

    public DetectorRule(String id, String name, String rule, List<String> tags) {
        this.name = name;
        this.id = id != null && !id.isEmpty()? id: UUID.randomUUID().toString();
        this.rule = rule;
        this.tags = tags != null? tags: new ArrayList<>();

        validateRule(this.name);
        for (String tag: this.tags) {
            validateRule(tag);
        }
    }

    public DetectorRule(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readString(), sin.readString(), sin.readStringList());
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(
                RULE_ID_FIELD, id,
                NAME_FIELD, name,
                RULE_FIELD, rule,
                TAGS_FIELD, tags
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeString(name);
        out.writeString(rule);
        out.writeStringCollection(tags);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        String[] tagArray = new String[]{};
        tagArray = tags.toArray(tagArray);

        builder.startObject()
                .field(RULE_ID_FIELD, id)
                .field(NAME_FIELD, name)
                .field(RULE_FIELD, rule)
                .field(TAGS_FIELD, tagArray)
                .endObject();
        return builder;
    }

    public static DetectorRule parse(XContentParser xcp) throws IOException {
        String id = UUID.randomUUID().toString();
        String rule = null;
        String name = null;
        List<String> tags = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case RULE_ID_FIELD:
                    id = xcp.text();
                    break;
                case NAME_FIELD:
                    name = xcp.text();
                    validateRule(name);
                    break;
                case RULE_FIELD:
                    rule = xcp.text();
                    break;
                case TAGS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        String tag = xcp.text();
                        validateRule(tag);
                        tags.add(tag);
                    }
            }
        }
        return new DetectorRule(id, name, rule, tags);
    }

    public static DetectorRule readFrom(StreamInput sin) throws IOException {
        return new DetectorRule(sin);
    }

    private static void validateRule(String stringVal) {
        for (String inValidChar: INVALID_CHARACTERS) {
            if (stringVal.contains(inValidChar)) {
                throw new IllegalArgumentException(String.format(Locale.getDefault(),
                        "They query name or tag, %s, contains an invalid character: [' ','[',']','{','}','(',')']", stringVal));
            }
        }
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getRule() {
        return rule;
    }

    public List<String> getTags() {
        return tags;
    }
}