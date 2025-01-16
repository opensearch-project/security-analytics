package org.opensearch.securityanalytics.threatIntel.model;

import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;

/**
 * Encapsulates data required to extract value for a field from data based on schema
 */
public class JsonPathSchemaField implements Writeable, ToXContentObject {
    public static final String JSON_PATH_FIELD = "json_path";
    public static final String IS_KEY_FIELD = "is_key";

    private final String jsonPath;
    private final boolean isKey;

    public JsonPathSchemaField(String jsonPath, boolean isKey) {
        this.jsonPath = jsonPath;
        this.isKey = isKey;
    }

    public JsonPathSchemaField(StreamInput in) throws IOException {
        this(in.readString(), in.readBoolean());
    }

    public static JsonPathSchemaField parse(XContentParser xcp) throws IOException {
        String jsonPath1 = "";
        boolean isKey1 = false;
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case JSON_PATH_FIELD:
                    jsonPath1 = xcp.text();
                    break;
                case IS_KEY_FIELD:
                    isKey1 = xcp.booleanValue();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new JsonPathSchemaField(jsonPath1, isKey1);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(jsonPath);
        out.writeBoolean(isKey);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(JSON_PATH_FIELD, jsonPath);
        builder.field(IS_KEY_FIELD, isKey);
        return builder.endObject();
    }

    public String getJsonPath() {
        return jsonPath;
    }

    public boolean isKey() {
        return isKey;
    }
}
