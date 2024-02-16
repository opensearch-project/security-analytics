/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.validators;

import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.when;

public class StreamingDetectorValidatorsTests extends OpenSearchTestCase {
    @Mock
    private Detector detector;
    @Mock
    private DetectorInput detectorInput;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);

        when(detector.getEnabled()).thenReturn(true);
        when(detector.isStreamingDetector()).thenReturn(true);
        when(detector.getInputs()).thenReturn(List.of(detectorInput));
        when(detector.getWorkflowIds()).thenReturn(List.of(UUID.randomUUID().toString()));
        when(detector.getMonitorIds()).thenReturn(List.of(UUID.randomUUID().toString()));
    }

    public void testValidDetector() {
        assertTrue(StreamingDetectorValidators.isDetectorValidForStreaming(detector));
    }

    public void testInvalidEnabledIsNull() {
        when(detector.getEnabled()).thenReturn(null);
        assertFalse(StreamingDetectorValidators.isDetectorValidForStreaming(detector));
    }

    public void testInvalidDisabled() {
        when(detector.getEnabled()).thenReturn(false);
        assertFalse(StreamingDetectorValidators.isDetectorValidForStreaming(detector));
    }

    public void testInvalidNotStreaming() {
        when(detector.isStreamingDetector()).thenReturn(false);
        assertFalse(StreamingDetectorValidators.isDetectorValidForStreaming(detector));
    }

    public void testInvalidInputsLength() {
        when(detector.getInputs()).thenReturn(List.of(detectorInput, detectorInput));
        assertFalse(StreamingDetectorValidators.isDetectorValidForStreaming(detector));
    }

    public void testInvalidWorkflowIdsLength() {
        when(detector.getWorkflowIds()).thenReturn(List.of(UUID.randomUUID().toString(), UUID.randomUUID().toString()));
        assertFalse(StreamingDetectorValidators.isDetectorValidForStreaming(detector));
    }

    public void testInvalidMonitorIdsLength() {
        when(detector.getMonitorIds()).thenReturn(Collections.emptyList());
        assertFalse(StreamingDetectorValidators.isDetectorValidForStreaming(detector));
    }

    public void testInvalidMultipleElements() {
        when(detector.getEnabled()).thenReturn(false);
        when(detector.isStreamingDetector()).thenReturn(false);
        when(detector.getMonitorIds()).thenReturn(Collections.emptyList());
        assertFalse(StreamingDetectorValidators.isDetectorValidForStreaming(detector));
    }
}
