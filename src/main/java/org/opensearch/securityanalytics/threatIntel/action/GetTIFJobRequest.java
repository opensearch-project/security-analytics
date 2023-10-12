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

/**
 * threat intel tif job get request
 */
public class GetTIFJobRequest extends ActionRequest {
    /**
     * @param names the tif job names
     * @return the tif job names
     */
    private String[] names;

    /**
     * Constructs a new get tif job request with a list of tif jobs.
     *
     * If the list of tif jobs is empty or it contains a single element "_all", all registered tif jobs
     * are returned.
     *
     * @param names list of tif job names
     */
    public GetTIFJobRequest(final String[] names) {
        this.names = names;
    }

    /**
     * Constructor with stream input
     * @param in the stream input
     * @throws IOException IOException
     */
    public GetTIFJobRequest(final StreamInput in) throws IOException {
        super(in);
        this.names = in.readStringArray();
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException errors = null;
        if (names == null) {
            errors = new ActionRequestValidationException();
            errors.addValidationError("names should not be null");
        }
        return errors;
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeStringArray(names);
    }

    public String[] getNames() {
        return this.names;
    }
}
