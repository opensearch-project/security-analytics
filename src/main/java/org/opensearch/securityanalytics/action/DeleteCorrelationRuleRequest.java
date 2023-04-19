/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import java.io.IOException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.ValidateActions;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.model.CorrelationRule;

public class DeleteCorrelationRuleRequest extends ActionRequest {

    private String correlationRuleId;
    private WriteRequest.RefreshPolicy refreshPolicy;

    public DeleteCorrelationRuleRequest(String correlationRuleId, WriteRequest.RefreshPolicy refreshPolicy) {
        super();
        this.correlationRuleId = correlationRuleId;
        this.refreshPolicy = refreshPolicy;
    }

    public DeleteCorrelationRuleRequest(StreamInput sin) throws IOException {
        this(sin.readString(), WriteRequest.RefreshPolicy.readFrom(sin));
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (correlationRuleId == null) {
            validationException = ValidateActions.addValidationError("Correlation Rule Id is mandatory!", validationException);
        }
        if (refreshPolicy == null) {
            validationException = ValidateActions.addValidationError("RefreshPolicy is mandatory!", validationException);
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(correlationRuleId);
        refreshPolicy.writeTo(out);
    }

    public String getCorrelationRuleId() {
        return correlationRuleId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }
}
