/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper.action.mapping;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.ParseField;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ObjectParser;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;

import java.io.IOException;

import static org.opensearch.action.ValidateActions.addValidationError;

public class UpdateIndexMappingsRequest extends ActionRequest {

    private static final ObjectParser<UpdateIndexMappingsRequest, Void> PARSER
            = new ObjectParser(
                    SecurityAnalyticsPlugin.PLUGIN_NAME_URI + SecurityAnalyticsPlugin.MAPPER_BASE_URI + "/update");
    static {
        PARSER.declareString(UpdateIndexMappingsRequest::setIndexName, new ParseField("indexName"));
        PARSER.declareString(UpdateIndexMappingsRequest::setField, new ParseField("field"));
        PARSER.declareString(UpdateIndexMappingsRequest::setAlias, new ParseField("alias"));
    }

    String indexName;
    String field;
    String alias;
    public UpdateIndexMappingsRequest() {}

    public UpdateIndexMappingsRequest(String indexName, String field, String alias) {
        this.indexName = indexName;
        this.field = field;
        this.alias = alias;
    }

    public UpdateIndexMappingsRequest(StreamInput in) throws IOException {
        super(in);
        indexName = in.readString();
        field = in.readString();
        alias = in.readString();
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (indexName == null || indexName.length() == 0) {
            validationException = addValidationError("indexName is missing", validationException);
        }
        if (field == null || field.length() == 0) {
            validationException = addValidationError("field is missing", validationException);
        }
        if (alias == null || alias.length() == 0) {
            validationException = addValidationError("alias is missing", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(indexName);
        out.writeString(field);
        out.writeString(alias);
    }

    public static UpdateIndexMappingsRequest parse(XContentParser parser) throws IOException {
        return PARSER.parse(parser, new UpdateIndexMappingsRequest(), null);
    }

    public UpdateIndexMappingsRequest indexName(String indexName) {
        this.indexName = indexName;
        return this;
    }

    public UpdateIndexMappingsRequest field(String field) {
        this.field = field;
        return this;
    }

    public UpdateIndexMappingsRequest alias(String alias) {
        this.alias = alias;
        return this;
    }

    public void setField(String field) {
        this.field = field;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public void setIndexName(String indexName) {
        this.indexName = indexName;
    }
}
