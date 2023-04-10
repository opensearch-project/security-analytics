/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

public class Value implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(Value.class);

    private static final String VALUE_FIELD = "value";

    private String value;

    public Value(String value) {
        this.value = value;
    }

    public Value(StreamInput sin) throws IOException {
        this(sin.readString());
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(value);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(VALUE_FIELD, value)
                .endObject();
    }

    public static Value parse(XContentParser xcp) throws IOException {
        String value = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case VALUE_FIELD:
                    value = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        return new Value(value);
    }

    public static Value readFrom(StreamInput sin) throws IOException {
        return new Value(sin);
    }

    public String getValue() {
        return value;
    }
}