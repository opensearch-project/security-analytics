package org.opensearch.securityanalytics.threatIntel.model;

import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;

public class IocSchema implements Writeable, ToXContentObject {

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

    private final SchemaField id;
    private final SchemaField name;
    private final SchemaField type;
    private final SchemaField value;
    private final SchemaField severity;
    private final SchemaField created;
    private final SchemaField modified;
    private final SchemaField description;
    private final SchemaField labels;
    private final SchemaField specVersion;

    public IocSchema(String idPath, String namePath, String typePath, String valuePath,
                     String severityPath, String createdPath, String modifiedPath,
                     String descriptionPath, String labelsPath, String specVersionPath) {
        this.id = new SchemaField(FIELD_ID, idPath);
        this.name = new SchemaField(FIELD_NAME, namePath);
        this.type = new SchemaField(FIELD_TYPE, typePath);
        this.value = new SchemaField(FIELD_VALUE, valuePath);
        this.severity = new SchemaField(FIELD_SEVERITY, severityPath);
        this.created = new SchemaField(FIELD_CREATED, createdPath);
        this.modified = new SchemaField(FIELD_MODIFIED, modifiedPath);
        this.description = new SchemaField(FIELD_DESCRIPTION, descriptionPath);
        this.labels = new SchemaField(FIELD_LABELS, labelsPath);
        this.specVersion = new SchemaField(FIELD_SPEC_VERSION, specVersionPath);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        id.writeTo(out);
        name.writeTo(out);
        type.writeTo(out);
        value.writeTo(out);
        severity.writeTo(out);
        created.writeTo(out);
        modified.writeTo(out);
        description.writeTo(out);
        labels.writeTo(out);
        specVersion.writeTo(out);
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

    public static IocSchema parse(XContentParser parser) throws IOException {
        String idPath = null;
        String namePath = null;
        String typePath = null;
        String valuePath = null;
        String severityPath = null;
        String createdPath = null;
        String modifiedPath = null;
        String descriptionPath = null;
        String labelsPath = null;
        String specVersionPath = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();

            switch (fieldName) {
                case FIELD_ID:
                    idPath = parser.text();
                    break;
                case FIELD_NAME:
                    namePath = parser.text();
                    break;
                case FIELD_TYPE:
                    typePath = parser.text();
                    break;
                case FIELD_VALUE:
                    valuePath = parser.text();
                    break;
                case FIELD_SEVERITY:
                    severityPath = parser.text();
                    break;
                case FIELD_CREATED:
                    createdPath = parser.text();
                    break;
                case FIELD_MODIFIED:
                    modifiedPath = parser.text();
                    break;
                case FIELD_DESCRIPTION:
                    descriptionPath = parser.text();
                    break;
                case FIELD_LABELS:
                    labelsPath = parser.text();
                    break;
                case FIELD_SPEC_VERSION:
                    specVersionPath = parser.text();
                    break;
                default:
                    parser.skipChildren();
            }
        }

        return new IocSchema(
                idPath, namePath, typePath, valuePath,
                severityPath, createdPath, modifiedPath,
                descriptionPath, labelsPath, specVersionPath
        );
    }

    /** Encapsulates data required to extract value for a field from data based on schema*/
    private static class SchemaField implements Writeable, ToXContentObject {
        private final String fieldName;
        private final String jsonPath;
        private final boolean isKey;

        public SchemaField(String fieldName, String jsonPath) {
            this(fieldName, jsonPath, false);
        }

        public SchemaField(String fieldName, String jsonPath, boolean isKey) {
            this.fieldName = fieldName;
            this.jsonPath = jsonPath;
            this.isKey = isKey;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            out.writeString(fieldName);
            out.writeString(jsonPath);
            out.writeBoolean(isKey);
        }

        @Override
        public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
            builder.startObject();
            builder.field("fieldName", fieldName);
            builder.field("jsonPath", jsonPath);
            builder.field("isKey", isKey);
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