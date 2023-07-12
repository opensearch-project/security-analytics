/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.opensearch.securityanalytics.model.CorrelationRule;

public class IndexCorrelationRuleRequest extends ActionRequest {

    private String correlationRuleId;

    private CorrelationRule correlationRule;

    private RestRequest.Method method;

    private static final Pattern IS_VALID_RULE_NAME = Pattern.compile("[a-zA-Z0-9 _,-.]{5,50}");

    public IndexCorrelationRuleRequest(String correlationRuleId, CorrelationRule correlationRule, RestRequest.Method method) {
        super();
        this.correlationRuleId = correlationRuleId;
        this.correlationRule = correlationRule;
        this.method = method;
    }

    public IndexCorrelationRuleRequest(StreamInput sin) throws IOException {
        this(sin.readString(), CorrelationRule.readFrom(sin), sin.readEnum(RestRequest.Method.class));
    }

    @Override
    public ActionRequestValidationException validate() {
        Matcher matcher = IS_VALID_RULE_NAME.matcher(correlationRule.getName());
        boolean find = matcher.matches();
        if (!find) {
            throw new ActionRequestValidationException();
        }
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(correlationRuleId);
        correlationRule.writeTo(out);
    }

    public String getCorrelationRuleId() {
        return correlationRuleId;
    }

    public CorrelationRule getCorrelationRule() {
        return correlationRule;
    }

    public RestRequest.Method getMethod() {
        return method;
    }
}
