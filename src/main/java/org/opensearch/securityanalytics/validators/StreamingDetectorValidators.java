/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.validators;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.securityanalytics.model.Detector;

import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public enum StreamingDetectorValidators {
    ENABLED_VALIDATOR("enabled", detector -> detector.getEnabled() != null && detector.getEnabled()),
    STREAMING_VALIDATOR("streaming_detector", Detector::isStreamingDetector),
    INPUTS_VALIDATOR("inputs", detector -> detector.getInputs().size() == 1),
    WORKFLOW_IDS_VALIDATOR("workflow_ids", detector -> detector.getWorkflowIds().size() == 1),
    MONITOR_IDS_VALIDATOR("monitor_ids", detector -> detector.getMonitorIds().size() > 0);

    private static final Logger log = LogManager.getLogger(StreamingDetectorValidators.class);

    private final String elementName;
    private final Predicate<Detector> validator;

    StreamingDetectorValidators(final String elementName, final Predicate<Detector> validator) {
        this.elementName = elementName;
        this.validator = validator;
    }

    public static boolean isDetectorValidForStreaming(final Detector detector) {
        final List<String> invalidElements = Arrays.stream(values())
                .filter(streamingDetectorValidator -> !streamingDetectorValidator.validator.test(detector))
                .map(streamingDetectorValidator -> streamingDetectorValidator.elementName)
                .collect(Collectors.toList());

        if (invalidElements.isEmpty()) {
            return true;
        }

        log.debug("Detector with name {} is invalid for streaming. Invalid elements: {}", detector.getName(), invalidElements);
        return false;
    }
}
