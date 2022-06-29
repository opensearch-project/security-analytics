/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.exceptions;

public class SigmaDetectionError extends SigmaError {

    public SigmaDetectionError(String message) {
        super(message);
    }
}