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
import org.opensearch.securityanalytics.model.CorrelationRule;

public class IndexCorrelationRuleRequest extends ActionRequest {

    private String correlationRuleId;

    private CorrelationRule correlationRule;

    private RestRequest.Method method;

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
