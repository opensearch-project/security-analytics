/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.Locale;

import static org.opensearch.action.ValidateActions.addValidationError;

public class GetRuleRequest extends ActionRequest {

    private String ruleId;
    private Boolean isPrepackaged;
    private Long version;

    public static final String RULE_ID = "ruleID";
    public static final String IS_PREPACKAGED = "pre_packaged";

    public GetRuleRequest(String ruleId, Boolean isPrepackaged, Long version) {
        super();
        this.ruleId = ruleId;
        this.isPrepackaged = isPrepackaged;
        this.version = version;
    }

    public GetRuleRequest(StreamInput sin) throws IOException {
        this(sin.readString(),
            sin.readBoolean(),
            sin.readLong());
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (ruleId == null || ruleId.length() == 0 || isPrepackaged) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", RULE_ID), validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(ruleId);
        out.writeLong(version);
    }

    public String getRuleId() {
        return ruleId;
    }

    public Boolean isPrepackaged() {
        return isPrepackaged;
    }

    public Long getVersion() {
        return version;
    }
}
