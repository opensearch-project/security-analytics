/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.securityanalytics.threatIntel.common.ParameterValidator;

import java.io.IOException;

/**
 * Threat intel datasource delete request
 */

public class DeleteDatasourceRequest extends ActionRequest {
    private static final ParameterValidator VALIDATOR = new ParameterValidator();
    /**
     * @param name the datasource name
     * @return the datasource name
     */
    private String name;

    /**
     * Constructor
     *
     * @param in the stream input
     * @throws IOException IOException
     */
    public DeleteDatasourceRequest(final StreamInput in) throws IOException {
        super(in);
        this.name = in.readString();
    }

    public DeleteDatasourceRequest(final String name) {
        this.name = name;
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException errors = null;
        if (VALIDATOR.validateDatasourceName(name).isEmpty() == false) {
            errors = new ActionRequestValidationException();
            errors.addValidationError("no such datasource exist");
        }
        return errors;
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(name);
    }

    public String getName() {
        return name;
    }
}
