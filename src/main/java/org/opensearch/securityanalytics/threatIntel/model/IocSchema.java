package org.opensearch.securityanalytics.threatIntel.model;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;

/**
 * Stores the schema defined by users who upload threat intelligence in a custom format.
 */
public abstract class IocSchema<Notation> implements Writeable, ToXContentObject {

    abstract String getFormat(); // data format like json, xml, csv etc.

    abstract Notation getId();

    abstract Notation getName();

    abstract Notation getType();

    abstract Notation getValue();

    abstract Notation getSeverity();

    abstract Notation getCreated();

    abstract Notation getModified();

    abstract Notation getDescription();

    abstract Notation getLabels();

    abstract Notation getSpecVersion();

    static JsonPathIocSchema readFrom(StreamInput sin) throws IOException {
        String format = sin.readString();
        switch (format) {
            case JsonPathIocSchema.JSON_PATH_DATA_FORMAT:
                return new JsonPathIocSchema(sin);
            default:
                throw new IllegalStateException("Unexpected ioc schema format [" + format + "] found while reading parse stream");
        }
    }

    static IocSchema parse(XContentParser xcp) throws IOException {
        IocSchema schema = null;
        ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case JsonPathIocSchema.JSON_PATH_DATA_FORMAT:
                    schema = JsonPathIocSchema.parse(xcp);
                    break;
                default:
                    throw new IllegalStateException("Unexpected ioc schema format [" + fieldName + "] found while parsing");
            }
        }
        return schema;
    }
}
