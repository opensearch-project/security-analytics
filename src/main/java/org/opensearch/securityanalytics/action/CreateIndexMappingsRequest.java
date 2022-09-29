/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.Locale;

import static org.opensearch.action.ValidateActions.addValidationError;

public class CreateIndexMappingsRequest extends ActionRequest implements ToXContentObject {

    public static final String INDEX_NAME_FIELD = "index_name";
    public static final String RULE_TOPIC_FIELD = "rule_topic";
    public static final String PARTIAL_FIELD = "partial";

    public static final Boolean PARTIAL_FIELD_DEFAULT_VALUE = true;

    String indexName;
    String ruleTopic;
    Boolean partial;

    public CreateIndexMappingsRequest(String indexName, String ruleTopic, Boolean partial) {
        super();
        this.indexName = indexName;
        this.ruleTopic = ruleTopic;
        this.partial = partial == null ? PARTIAL_FIELD_DEFAULT_VALUE : partial;
    }

    public CreateIndexMappingsRequest(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readString(),
                sin.readBoolean()
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (indexName == null || indexName.length() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", INDEX_NAME_FIELD), validationException);
        }
        if (ruleTopic == null || ruleTopic.length() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", RULE_TOPIC_FIELD), validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(indexName);
        out.writeString(ruleTopic);
        out.writeBoolean(partial);
    }

    public static CreateIndexMappingsRequest parse(XContentParser xcp) throws IOException {
        String indexName = null;
        String ruleTopic = null;
        Boolean partial = null;

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
                case RULE_TOPIC_FIELD:
                    ruleTopic = xcp.text();
                    break;
                case PARTIAL_FIELD:
                    partial = xcp.booleanValue();
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new CreateIndexMappingsRequest(indexName, ruleTopic, partial);
    }

    public CreateIndexMappingsRequest indexName(String indexName) {
        this.indexName = indexName;
        return this;
    }

    public CreateIndexMappingsRequest ruleTopic(String ruleTopic) {
        this.ruleTopic = ruleTopic;
        return this;
    }

    public CreateIndexMappingsRequest partial(Boolean partial) {
        this.partial = partial;
        return this;
    }

    public String getRuleTopic() {
        return this.ruleTopic;
    }

    public String getIndexName() {
        return this.indexName;
    }

    public Boolean getPartial() {
        return this.partial;
    }

    public void setRuleTopic(String ruleTopic) {
        this.ruleTopic = ruleTopic;
    }

    public void setIndexName(String indexName) {
        this.indexName = indexName;
    }

    public void setPartial(Boolean partial) {
        this.partial = partial;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(INDEX_NAME_FIELD, indexName)
                .field(RULE_TOPIC_FIELD, ruleTopic)
                .field(PARTIAL_FIELD, partial)
                .endObject();
    }
}
