package org.opensearch.securityanalytics.threatIntel.model;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;

/**
 * Stores the schema defined by users who upload threat intelligence in a custom format.
 * Each field is defined and extracted using {@link com.jayway.jsonpath.JsonPath} annotation.
 * Each field is of type {@link JsonPathSchemaField}
 */
public class JsonPathIocSchema extends IocSchema<JsonPathSchemaField> {
    private static final Logger log = LogManager.getLogger(JsonPathIocSchema.class);
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
    public static final String JSON_PATH_DATA_FORMAT = "json_path_schema";

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
        builder.startObject(JSON_PATH_DATA_FORMAT);
        jsonPathSchemaFieldToXcontent(builder, params, id, FIELD_ID);
        jsonPathSchemaFieldToXcontent(builder, params, name, FIELD_NAME);
        jsonPathSchemaFieldToXcontent(builder, params, type, FIELD_TYPE);
        jsonPathSchemaFieldToXcontent(builder, params, value, FIELD_VALUE);
        jsonPathSchemaFieldToXcontent(builder, params, severity, FIELD_SEVERITY);
        jsonPathSchemaFieldToXcontent(builder, params, created, FIELD_CREATED);
        jsonPathSchemaFieldToXcontent(builder, params, modified, FIELD_MODIFIED);
        jsonPathSchemaFieldToXcontent(builder, params, description, FIELD_DESCRIPTION);
        jsonPathSchemaFieldToXcontent(builder, params, labels, FIELD_LABELS);
        jsonPathSchemaFieldToXcontent(builder, params, specVersion, FIELD_SPEC_VERSION);
        builder.endObject();
        return builder.endObject();
    }

    // performs null check before converting to Xcontent
    private void jsonPathSchemaFieldToXcontent(XContentBuilder builder, Params params, JsonPathSchemaField jsonPathSchemaField, String fieldName) throws IOException {
        if (jsonPathSchemaField != null) {
            builder.field(fieldName, jsonPathSchemaField);
        }
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

}