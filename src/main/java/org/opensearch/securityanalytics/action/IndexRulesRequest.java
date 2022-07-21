/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.List;

public class IndexRulesRequest extends ActionRequest {

    private WriteRequest.RefreshPolicy refreshPolicy;

    private String ruleTopic;

    private String rule;

    private RestRequest.Method method;

    public IndexRulesRequest(
            WriteRequest.RefreshPolicy refreshPolicy,
            String ruleTopic,
            String rule,
            RestRequest.Method method) {
        super();
        this.refreshPolicy = refreshPolicy;
        this.ruleTopic = ruleTopic;
        this.rule = rule;
        this.method = method;
    }

    public IndexRulesRequest(StreamInput sin) throws IOException {
        this(WriteRequest.RefreshPolicy.readFrom(sin),
             sin.readString(),
             sin.readString(),
             sin.readEnum(RestRequest.Method.class));
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        refreshPolicy.writeTo(out);
        out.writeString(ruleTopic);
        out.writeString(rule);
        out.writeEnum(method);
    }

    public String getRuleTopic() {
        return ruleTopic;
    }

    public String getRule() {
        return rule;
    }

    public RestRequest.Method getMethod() {
        return method;
    }
}