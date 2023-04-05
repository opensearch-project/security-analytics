/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.Locale;

import static org.opensearch.action.ValidateActions.addValidationError;

public class UpdateIndexMappingsRequest extends ActionRequest implements ToXContentObject {

    public static final String INDEX_NAME_FIELD = "index_name";
    public static final String FIELD = "field";
    public static final String ALIAS = "alias";

    String indexName;
    String field;
    String alias;

    public UpdateIndexMappingsRequest(String indexName, String field, String alias) {
        super();
        this.indexName = indexName;
        this.field = field;
        this.alias = alias;
    }

    public UpdateIndexMappingsRequest(StreamInput sin) throws IOException {
        this (
                sin.readString(),
                sin.readString(),
                sin.readString()
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (indexName == null || indexName.length() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", INDEX_NAME_FIELD), validationException);
        }
        if (field == null || field.length() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", FIELD), validationException);
        }
        if (alias == null || alias.length() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", ALIAS), validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(indexName);
        out.writeString(field);
        out.writeString(alias);
    }

    public static UpdateIndexMappingsRequest parse(XContentParser xcp) throws IOException {
        String indexName = null;
        String field = null;
        String alias = null;

        if (xcp.currentToken() == null) {
            xcp.nextToken();
        }
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case INDEX_NAME_FIELD:
                    indexName = xcp.text();
                    break;
                case FIELD:
                    field = xcp.text();
                    break;
                case ALIAS:
                    alias = xcp.text();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new UpdateIndexMappingsRequest(indexName, field, alias);
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

    public String getField() {
        return this.field;
    }

    public String getAlias() {
        return this.alias;
    }

    public String getIndexName() {
        return this.indexName;
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

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(INDEX_NAME_FIELD, indexName)
                .field(FIELD, field)
                .field(ALIAS, alias)
                .endObject();
    }
}
