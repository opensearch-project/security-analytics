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
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.Locale;

import static org.opensearch.action.ValidateActions.addValidationError;

public class GetIndexMappingsRequest extends ActionRequest {

    public static final String INDEX_NAME_FIELD = "index_name";

    String indexName;

    public GetIndexMappingsRequest(String indexName) {
        super();
        this.indexName = indexName;
    }

    public GetIndexMappingsRequest(StreamInput sin) throws IOException {
        this (
              sin.readString()
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (indexName == null || indexName.length() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", INDEX_NAME_FIELD), validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(indexName);
    }

    public static GetIndexMappingsRequest parse(XContentParser xcp) throws IOException {
        String indexName = null;

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
                default:
                    xcp.skipChildren();
            }
        }
        return new GetIndexMappingsRequest(indexName);
    }

    public GetIndexMappingsRequest indexName(String indexName) {
        this.indexName = indexName;
        return this;
    }

    public String getIndexName() {
        return this.indexName;
    }

    public void setIndexName(String indexName) {
        this.indexName = indexName;
    }
}
