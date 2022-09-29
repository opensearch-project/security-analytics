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

public class IndexRuleRequest extends ActionRequest {

    /**
     * the ruleId to update
     */
    private String ruleId;

    /**
     * refreshPolicy for create/update
     */
    private WriteRequest.RefreshPolicy refreshPolicy;

    /**
     * the log type of the rule which has 1-1 mapping to log type. We have 8 pre-defined log types today.
     */
    private String logType;

    /**
     * REST method for the request PUT/POST
     */
    private RestRequest.Method method;

    /**
     * the actual Sigma Rule yaml
     */
    private String rule;

    /**
     * this boolean field forces updating of rule from any running detectors & updates detector metadata.
     * setting this to false, will result in throwing an error if rule is actively used by other detectors.
     */
    private Boolean forced;

    public IndexRuleRequest(
            String ruleId,
            WriteRequest.RefreshPolicy refreshPolicy,
            String logType,
            RestRequest.Method method,
            String rule,
            Boolean forced
    ) {
        super();
        this.ruleId = ruleId;
        this.refreshPolicy = refreshPolicy;
        this.logType = logType;
        this.method = method;
        this.rule = rule;
        this.forced = forced;
    }

    public IndexRuleRequest(StreamInput sin) throws IOException {
        this(sin.readString(),
             WriteRequest.RefreshPolicy.readFrom(sin),
             sin.readString(),
             sin.readEnum(RestRequest.Method.class),
             sin.readString(),
             sin.readBoolean());
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(ruleId);
        refreshPolicy.writeTo(out);
        out.writeString(logType);
        out.writeEnum(method);
        out.writeString(rule);
        out.writeBoolean(forced);
    }

    public String getRuleId() {
        return ruleId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }

    public String getLogType() {
        return logType;
    }

    public RestRequest.Method getMethod() {
        return method;
    }

    public String getRule() {
        return rule;
    }

    public Boolean isForced() {
        return forced;
    }
}