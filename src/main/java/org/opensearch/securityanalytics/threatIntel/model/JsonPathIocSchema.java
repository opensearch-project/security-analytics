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
 * Stores the schema defined by users who upload threat intelligence in a custom format.
 * Each field is defined and extracted using {@link com.jayway.jsonpath.JsonPath} annotation.
 * Each field is of type {@link JsonPathSchemaField}
 * If value of any given field is stored in format {"<key>": "<value>"}, then value of {@link JsonPathSchemaField#isKey()} field should be set as false.
 * Else if value is stored in key itself, then value of {@link JsonPathSchemaField#isKey()} field should be set to true.
 */
public class JsonPathIocSchema extends IocSchema<JsonPathIocSchema.JsonPathSchemaField> {

    public static final String FIELD_ID = "id";
    public static final String FIELD_NAME = "name";
    public static final String FIELD_TYPE = "type";
    public static final String FIELD_VALUE = "value";
    public static final String FIELD_SEVERITY = "severity";
    public static final String FIELD_CREATED = "created";
    public static final String FIELD_MODIFIED = "modified";
    public static final String FIELD_DESCRIPTION = "description";
    public static final String FIELD_LABELS = "labels";
    public static final String FIELD_SPEC_VERSION = "spec_version";
    public static final String JSON_PATH_DATA_FORMAT = "JSON_PATH";

    private final JsonPathSchemaField id;
    private final JsonPathSchemaField name;
    private final JsonPathSchemaField type;
    private final JsonPathSchemaField value;
    private final JsonPathSchemaField severity;
    private final JsonPathSchemaField created;
    private final JsonPathSchemaField modified;
    private final JsonPathSchemaField description;
    private final JsonPathSchemaField labels;
    private final JsonPathSchemaField specVersion;

    public JsonPathIocSchema(JsonPathSchemaField id, JsonPathSchemaField name, JsonPathSchemaField type, JsonPathSchemaField value, JsonPathSchemaField severity,
                             JsonPathSchemaField created, JsonPathSchemaField modified, JsonPathSchemaField description, JsonPathSchemaField labels,
                             JsonPathSchemaField specVersion) {
        this.id = id;
        this.name = name;
        this.type = type;
        this.value = value;
        this.severity = severity;
        this.created = created;
        this.modified = modified;
        this.description = description;
        this.labels = labels;
        this.specVersion = specVersion;
    }

    public JsonPathIocSchema(StreamInput in) throws IOException {
        this(
                readOptionalSchemaField(in), //id
                readOptionalSchemaField(in), //name
                readOptionalSchemaField(in), //type
                readOptionalSchemaField(in), //value
                readOptionalSchemaField(in), //severity
                readOptionalSchemaField(in), //created
                readOptionalSchemaField(in), //modified
                readOptionalSchemaField(in), //description
                readOptionalSchemaField(in), //labels
                readOptionalSchemaField(in) //specVersion
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        writeOptionalSchemaField(id, out);
        writeOptionalSchemaField(name, out);
        writeOptionalSchemaField(type, out);
        writeOptionalSchemaField(value, out);
        writeOptionalSchemaField(severity, out);
        writeOptionalSchemaField(created, out);
        writeOptionalSchemaField(modified, out);
        writeOptionalSchemaField(description, out);
        writeOptionalSchemaField(labels, out);
        writeOptionalSchemaField(specVersion, out);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(FIELD_ID, id.toXContent(builder, params));
        builder.field(FIELD_NAME, name.toXContent(builder, params));
        builder.field(FIELD_TYPE, type.toXContent(builder, params));
        builder.field(FIELD_VALUE, value.toXContent(builder, params));
        builder.field(FIELD_SEVERITY, severity.toXContent(builder, params));
        builder.field(FIELD_CREATED, created.toXContent(builder, params));
        builder.field(FIELD_MODIFIED, modified.toXContent(builder, params));
        builder.field(FIELD_DESCRIPTION, description.toXContent(builder, params));
        builder.field(FIELD_LABELS, labels.toXContent(builder, params));
        builder.field(FIELD_SPEC_VERSION, specVersion.toXContent(builder, params));
        return builder.endObject();
    }

    public static JsonPathIocSchema parse(XContentParser parser) throws IOException {
        JsonPathSchemaField idPath = null;
        JsonPathSchemaField namePath = null;
        JsonPathSchemaField typePath = null;
        JsonPathSchemaField valuePath = null;
        JsonPathSchemaField severityPath = null;
        JsonPathSchemaField createdPath = null;
        JsonPathSchemaField modifiedPath = null;
        JsonPathSchemaField descriptionPath = null;
        JsonPathSchemaField labelsPath = null;
        JsonPathSchemaField specVersionPath = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();

            switch (fieldName) {
                case FIELD_ID:
                    idPath = JsonPathSchemaField.parse(parser);
                    break;
                case FIELD_NAME:
                    namePath = JsonPathSchemaField.parse(parser);
                    break;
                case FIELD_TYPE:
                    typePath = JsonPathSchemaField.parse(parser);
                    break;
                case FIELD_VALUE:
                    valuePath = JsonPathSchemaField.parse(parser);
                    break;
                case FIELD_SEVERITY:
                    severityPath = JsonPathSchemaField.parse(parser);
                    break;
                case FIELD_CREATED:
                    createdPath = JsonPathSchemaField.parse(parser);
                    break;
                case FIELD_MODIFIED:
                    modifiedPath = JsonPathSchemaField.parse(parser);
                    break;
                case FIELD_DESCRIPTION:
                    descriptionPath = JsonPathSchemaField.parse(parser);
                    break;
                case FIELD_LABELS:
                    labelsPath = JsonPathSchemaField.parse(parser);
                    break;
                case FIELD_SPEC_VERSION:
                    specVersionPath = JsonPathSchemaField.parse(parser);
                    break;
                default:
                    parser.skipChildren();
            }
        }

        return new JsonPathIocSchema(
                idPath, namePath, typePath, valuePath,
                severityPath, createdPath, modifiedPath,
                descriptionPath, labelsPath, specVersionPath
        );
    }

    public JsonPathSchemaField getId() {
        return id;
    }

    public JsonPathSchemaField getName() {
        return name;
    }

    public JsonPathSchemaField getType() {
        return type;
    }

    public JsonPathSchemaField getValue() {
        return value;
    }

    public JsonPathSchemaField getSeverity() {
        return severity;
    }

    public JsonPathSchemaField getCreated() {
        return created;
    }

    public JsonPathSchemaField getModified() {
        return modified;
    }

    public JsonPathSchemaField getDescription() {
        return description;
    }

    public JsonPathSchemaField getLabels() {
        return labels;
    }

    public JsonPathSchemaField getSpecVersion() {
        return specVersion;
    }

    @Override
    public String getFormat() {
        return JSON_PATH_DATA_FORMAT;
    }

    private static void writeOptionalSchemaField(JsonPathSchemaField jsonPathSchemaField, StreamOutput out) throws IOException {
        if (jsonPathSchemaField == null) {
            out.writeBoolean(false);
        } else {
            out.writeBoolean(true);
            jsonPathSchemaField.writeTo(out);
        }
    }

    private static JsonPathSchemaField readOptionalSchemaField(StreamInput in) throws IOException {
        return in.readBoolean() ? new JsonPathSchemaField(in) : null;
    }

    /**
     * Encapsulates data required to extract value for a field from data based on schema
     */
    static class JsonPathSchemaField implements Writeable, ToXContentObject {
        public static final String JSON_PATH_FIELD = "jsonPath";
        public static final String IS_KEY_FIELD = "isKey";

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
            String fieldName1 = "";
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
}