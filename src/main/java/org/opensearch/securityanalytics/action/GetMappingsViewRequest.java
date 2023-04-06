/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.Locale;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.collect.ImmutableOpenMap;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.XContentParser;


import static org.opensearch.action.ValidateActions.addValidationError;

public class GetMappingsViewRequest extends ActionRequest {

    public static final String INDEX_NAME_FIELD = "index_name";
    public static final String RULE_TOPIC_FIELD = "rule_topic";

    String indexName;
    String ruleTopic;

    public GetMappingsViewRequest(String indexName, String ruleTopic) {
        super();
        this.indexName = indexName;
        this.ruleTopic = ruleTopic;
    }

    public GetMappingsViewRequest(StreamInput sin) throws IOException {
        this (
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
        if (ruleTopic == null || ruleTopic.length() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", RULE_TOPIC_FIELD), validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(indexName);
        out.writeString(ruleTopic);
    }

    public static GetMappingsViewRequest parse(XContentParser xcp) throws IOException {
        String indexName = null;
        String ruleTopic = null;

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
                default:
                    xcp.skipChildren();
            }
        }
        return new GetMappingsViewRequest(indexName, ruleTopic);
    }

    public GetMappingsViewRequest indexName(String indexName) {
        this.indexName = indexName;
        return this;
    }

    public GetMappingsViewRequest ruleTopic(String ruleTopic) {
        this.ruleTopic = ruleTopic;
        return this;
    }

    public String getIndexName() {
        return this.indexName;
    }

    public String getRuleTopic() {
        return this.ruleTopic;
    }

    public void setRuleTopic(String ruleTopic) {
        this.ruleTopic = ruleTopic;
    }
}
