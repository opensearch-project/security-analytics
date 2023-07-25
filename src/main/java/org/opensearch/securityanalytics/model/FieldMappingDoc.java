/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.search.SearchHit;

public class FieldMappingDoc implements ToXContent, Writeable {

    public static final String RAW_FIELD = "raw_field";
    public static final String LOG_TYPES = "log_types";

    private String id;
    private String rawField;
    private String defaultSchemaFieldValue;
    private Map<String, String> schemaFields;
    private Set<String> logTypes;

    private boolean isDirty;

    public FieldMappingDoc(String id, String rawField, Map<String, String> schemaFields, Set<String> logTypes) {
        this(rawField, schemaFields, logTypes);
        this.id = id;
    }

    public FieldMappingDoc(String rawField, Map<String, String> schemaFields, Set<String> logTypes) {
        Objects.requireNonNull(schemaFields);
        Objects.requireNonNull(logTypes);
        this.rawField = rawField;
        this.schemaFields = schemaFields;
        this.logTypes = logTypes;
    }

    public FieldMappingDoc(String rawField, Set<String> logTypes) {
        this.rawField = rawField;
        this.schemaFields = new HashMap<>();
        this.logTypes = logTypes;
    }

    public FieldMappingDoc(StreamInput sin) throws IOException {
        this.rawField = sin.readString();
        this.schemaFields = sin.readMap(StreamInput::readString, StreamInput::readString);
        Collections.addAll(this.logTypes, sin.readStringArray());
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(RAW_FIELD, rawField);
        builder.mapContents(schemaFields);
        builder.array(LOG_TYPES, logTypes.toArray(new String[0]));
        return builder.endObject();
    }

    public static FieldMappingDoc parse(SearchHit hit, NamedXContentRegistry xContentRegistry) throws IOException {
        XContentParser xcp = XContentHelper.createParser(
                xContentRegistry,
                LoggingDeprecationHandler.INSTANCE,
                hit.getSourceRef(),
                XContentType.JSON
        );
        return parse(xcp, hit.getId());
    }

    public static FieldMappingDoc parse(XContentParser xcp, String id) throws IOException {
        String rawField = null;
        Map<String, String> schemaFields = new HashMap<>();
        Set<String> logTypes = new HashSet<>();
        if (xcp.currentToken() == null) {
            xcp.nextToken();
        }
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case RAW_FIELD:
                    rawField = xcp.text();
                    break;
                case LOG_TYPES:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        logTypes.add(xcp.text());
                    }
                    break;
                default:
                    if (xcp.textOrNull() != null) {
                        schemaFields.put(fieldName, xcp.text());
                    }
            }
        }
        return new FieldMappingDoc(id, rawField, schemaFields, logTypes);
    }


    public String getRawField() {
        return rawField;
    }

    public Map<String, String> getSchemaFields() {
        return schemaFields;
    }

    public Set<String> getLogTypes() {
        return logTypes;
    }

    public String getId() {
        return id;
    }

    public boolean isDirty() {
        return isDirty;
    }

    public void setIsDirty(boolean isDirty) {
        this.isDirty = isDirty;
    }

    public Object get(String field) {
        return schemaFields.get(field);
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(this.rawField);
        out.writeMap(schemaFields, StreamOutput::writeString, StreamOutput::writeString);
        out.writeStringArray(logTypes.toArray(new String[0]));
    }
}
