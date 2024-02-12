/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.validators;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.util.Arrays;
import java.util.function.Predicate;

public enum StreamingDetectorValidators {
    INPUTS_VALIDATOR("inputs", detector -> detector.getInputs().size() == 1),
    WORKFLOW_IDS_VALIDATOR("workflows", detector -> detector.getWorkflowIds().size() == 1),
    MONITOR_IDS_VALIDATOR("monitors", detector -> detector.getMonitorIds().size() == 1);

    private final String elementName;
    private final Predicate<Detector> validator;

    StreamingDetectorValidators(final String elementName, final Predicate<Detector> validator) {
        this.elementName = elementName;
        this.validator = validator;
    }

    public static void validateDetector(final Detector detector) {
        Arrays.stream(values()).forEach(detectorValidator -> {
            final boolean isValid = detectorValidator.validator.test(detector);
            if (!isValid) {
                final String errorMsg = String.format("Detector with ID %s is invalid for streaming. Invalid element: %s",
                        detector.getId(), detectorValidator.elementName);
                throw new SecurityAnalyticsException(
                        errorMsg,
                        RestStatus.INTERNAL_SERVER_ERROR,
                        null
                );
            }
        });
    }
}
