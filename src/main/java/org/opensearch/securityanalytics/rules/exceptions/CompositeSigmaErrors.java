/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.exceptions;

import java.util.ArrayList;
import java.util.List;

public class CompositeSigmaErrors extends Exception {
    private final List<SigmaError> errorList;

    public CompositeSigmaErrors() {
        this.errorList = new ArrayList<>();
    }

    public void addError(SigmaError error) {
        errorList.add(error);
    }

    public List<SigmaError> getErrors() {
        return errorList;
    }
}
