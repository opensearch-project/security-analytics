/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.exceptions;

public class SigmaRegularExpressionError extends SigmaError {

    public SigmaRegularExpressionError(String message) {
        super(message);
    }
}