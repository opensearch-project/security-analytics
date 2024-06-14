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
 * Refresh threat intel feed source config request
 */
public class SARefreshTIFSourceConfigRequest extends ActionRequest {
    private final String id;
    private final Long version;

    public SARefreshTIFSourceConfigRequest(String id, Long version) {
        super();
        this.id = id;
        this.version = version;
    }

    public SARefreshTIFSourceConfigRequest(StreamInput sin) throws IOException {
        this(sin.readString(), // id
             sin.readLong()); // version
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
    }

    public String getId() {
        return id;
    }

    public Long getVersion() {
        return version;
    }


    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (id == null || id.isBlank()) {
            validationException = addValidationError(String.format(Locale.getDefault(), "%s is missing", THREAT_INTEL_SOURCE_CONFIG_ID), validationException);
        }
        return validationException;
    }

}
