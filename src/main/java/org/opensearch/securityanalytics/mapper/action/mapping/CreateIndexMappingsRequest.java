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

public class CreateIndexMappingsRequest extends ActionRequest {

    private static final ObjectParser<CreateIndexMappingsRequest, Void> PARSER
            = new ObjectParser(
                    SecurityAnalyticsPlugin.PLUGIN_NAME_URI + SecurityAnalyticsPlugin.MAPPER_BASE_URI + "/update");
    static {
        PARSER.declareString(CreateIndexMappingsRequest::setIndexName, new ParseField("indexName"));
        PARSER.declareString(CreateIndexMappingsRequest::setRuleTopic, new ParseField("ruleTopic"));
    }

    String indexName;
    String ruleTopic;

    public CreateIndexMappingsRequest() {}

    public CreateIndexMappingsRequest(String indexName, String ruleTopic) {
        this.indexName = indexName;
        this.ruleTopic = ruleTopic;
    }

    public CreateIndexMappingsRequest(StreamInput in) throws IOException {
        super(in);
        indexName = in.readString();
        ruleTopic = in.readString();
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (indexName == null || indexName.length() == 0) {
            validationException = addValidationError("indexName is missing", validationException);
        }
        if (ruleTopic == null || ruleTopic.length() == 0) {
            validationException = addValidationError("mappings are missing", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(indexName);
        out.writeString(ruleTopic);
    }

    public static CreateIndexMappingsRequest parse(XContentParser parser) throws IOException {
        return PARSER.parse(parser, new CreateIndexMappingsRequest(), null);
    }

    public CreateIndexMappingsRequest indexName(String indexName) {
        this.indexName = indexName;
        return this;
    }

    public CreateIndexMappingsRequest ruleTopic(String ruleTopic) {
        this.ruleTopic = ruleTopic;
        return this;
    }

    public void setRuleTopic(String ruleTopic) {
        this.ruleTopic = ruleTopic;
    }

    public void setIndexName(String indexName) {
        this.indexName = indexName;
    }
}
