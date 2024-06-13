/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.Locale;

import static org.opensearch.action.ValidateActions.addValidationError;
import static org.opensearch.securityanalytics.threatIntel.common.Constants.THREAT_INTEL_SOURCE_CONFIG_ID;

/**
 * Delete threat intel feed source config request
 */
public class SADeleteTIFSourceConfigRequest extends ActionRequest {
    private final String id;
    public SADeleteTIFSourceConfigRequest(String id) {
        super();
        this.id = id;
    }

    public SADeleteTIFSourceConfigRequest(StreamInput sin) throws IOException {
        this(sin.readString()); // id
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
    }

    public String getId() {
        return id;
    }


    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (id == null || id.isEmpty()) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", THREAT_INTEL_SOURCE_CONFIG_ID), validationException);
        }
        return validationException;
    }

}
