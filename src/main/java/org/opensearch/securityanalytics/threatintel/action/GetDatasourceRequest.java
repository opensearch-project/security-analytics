/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

/**
 * threat intel datasource get request
 */
public class GetDatasourceRequest extends ActionRequest {
    /**
     * @param names the datasource names
     * @return the datasource names
     */
    private String[] names;

    /**
     * Constructs a new get datasource request with a list of datasources.
     *
     * If the list of datasources is empty or it contains a single element "_all", all registered datasources
     * are returned.
     *
     * @param names list of datasource names
     */
    public GetDatasourceRequest(final String[] names) {
        this.names = names;
    }

    /**
     * Constructor with stream input
     * @param in the stream input
     * @throws IOException IOException
     */
    public GetDatasourceRequest(final StreamInput in) throws IOException {
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
