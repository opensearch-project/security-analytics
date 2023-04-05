/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

public class DetectorRule implements Writeable, ToXContentObject {

    private String id;

    private static final List<String> INVALID_CHARACTERS = List.of(" ", "[", "]", "{", "}", "(", ")");

    protected static final String RULE_ID_FIELD = "id";

    public DetectorRule(String id) {
        if (id == null || id.isEmpty()) {
            throw new IllegalArgumentException("Custom Rule id is invalid");
        }
        this.id = id;
    }

    public DetectorRule(StreamInput sin) throws IOException {
        this(sin.readString());
    }

    public Map<String, Object> asTemplateArg() {
        return Map.of(
                RULE_ID_FIELD, id
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .field(RULE_ID_FIELD, id)
                .endObject();
        return builder;
    }

    public static DetectorRule parse(XContentParser xcp) throws IOException {
        String id = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case RULE_ID_FIELD:
                    id = xcp.text();
                    break;
            }
        }
        return new DetectorRule(id);
    }

    public static DetectorRule readFrom(StreamInput sin) throws IOException {
        return new DetectorRule(sin);
    }

    public String getId() {
        return id;
    }
}