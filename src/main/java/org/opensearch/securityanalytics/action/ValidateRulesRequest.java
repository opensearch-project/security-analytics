/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.Strings;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;


import static org.opensearch.action.ValidateActions.addValidationError;

public class ValidateRulesRequest extends ActionRequest implements ToXContentObject {

    private static final Logger log = LogManager.getLogger(ValidateRulesRequest.class);

    public static final String INDEX_NAME_FIELD = "index_name";
    public static final String RULES_FIELD = "rules";

    String indexName;
    List<String> rules;

    public ValidateRulesRequest(String indexName, List<String> rules) {
        super();
        this.indexName = indexName;
        this.rules = rules;
    }

    public ValidateRulesRequest(StreamInput sin) throws IOException {
        this(
            sin.readString(),
            sin.readStringList()
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (indexName == null || indexName.length() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", INDEX_NAME_FIELD), validationException);
        }
        if (rules == null || rules.size() == 0) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s are missing", RULES_FIELD), validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(indexName);
        out.writeStringCollection(rules);
    }

    public static ValidateRulesRequest parse(XContentParser xcp) throws IOException {
        String indexName = null;
        List<String> ruleIds = null;

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
                case RULES_FIELD:
                    ruleIds = new ArrayList<>();
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        ruleIds.add(xcp.text());
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }
        return new ValidateRulesRequest(indexName, ruleIds);
    }

    public ValidateRulesRequest indexName(String indexName) {
        this.indexName = indexName;
        return this;
    }

    public ValidateRulesRequest rules(List<String> rules) {
        this.rules = rules;
        return this;
    }



    public String getIndexName() {
        return this.indexName;
    }

    public List<String> getRules() {
        return this.rules;
    }

    public void setIndexName(String indexName) {
        this.indexName = indexName;
    }

    public List<String> setRules(List<String> rules) {
        return this.rules = rules;
    }


    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(INDEX_NAME_FIELD, indexName)
                .field(RULES_FIELD, rules)
                .endObject();
    }
}
