/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.converters;

import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DocData;
import org.opensearch.securityanalytics.model.StreamingDetectorMetadata;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.mockito.Mockito.when;

public class StreamingDetectorMetadataConverterTests extends OpenSearchTestCase {
    private static final String INDEX_NAME = UUID.randomUUID().toString();
    private static final String WORKFLOW_ID = UUID.randomUUID().toString();
    private static final String MONITOR_ID = UUID.randomUUID().toString();

    @Mock
    private Detector detector;
    @Mock
    private Detector detector2;
    @Mock
    private DetectorInput detectorInput;
    @Mock
    private DetectorInput detectorInput2;
    @Mock
    private DocData docData;

    private StreamingDetectorMetadataConverter converter;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        converter = new StreamingDetectorMetadataConverter();

        when(detector.getInputs()).thenReturn(List.of(detectorInput));
        when(detector.getWorkflowIds()).thenReturn(List.of(WORKFLOW_ID));
        when(detector.getMonitorIds()).thenReturn(List.of(MONITOR_ID));
        when(detector.getEnabled()).thenReturn(true);
        when(detector.isStreamingDetector()).thenReturn(true);
        when(detectorInput.getIndices()).thenReturn(List.of(INDEX_NAME));
    }

    public void testFiltersInvalidDetectors() {
        when(detector.isStreamingDetector()).thenReturn(false);

        final List<StreamingDetectorMetadata> result = converter.convert(List.of(detector), getIndexToDocData(Set.of(INDEX_NAME)));
        assertTrue(result.isEmpty());
    }

    public void testFiltersNoIndexMatchesDetectors() {
        when(detectorInput.getIndices()).thenReturn(List.of(UUID.randomUUID().toString()));

        final List<StreamingDetectorMetadata> result = converter.convert(List.of(detector), getIndexToDocData(Set.of(INDEX_NAME)));
        assertTrue(result.isEmpty());
    }

    public void testDetectorMatch() {
        final List<StreamingDetectorMetadata> result = converter.convert(List.of(detector), getIndexToDocData(Set.of(INDEX_NAME)));
        assertEquals(1, result.size());
        assertEquals(WORKFLOW_ID, result.get(0).getWorkflowId());
        assertEquals(List.of(MONITOR_ID), result.get(0).getMonitorIds());
        assertEquals(Set.of(INDEX_NAME), result.get(0).getIndexToDocData().keySet());
    }

    public void testDetectorMatchesOnlyOneIndex() {
        final Set<String> indexNames = Set.of(INDEX_NAME, UUID.randomUUID().toString(), UUID.randomUUID().toString());
        final String secondDetectorIndexName = UUID.randomUUID().toString();
        when(detectorInput.getIndices()).thenReturn(List.of(INDEX_NAME, secondDetectorIndexName));
        final List<StreamingDetectorMetadata> result = converter.convert(List.of(detector), getIndexToDocData(indexNames));
        assertEquals(1, result.size());
        assertEquals(WORKFLOW_ID, result.get(0).getWorkflowId());
        assertEquals(List.of(MONITOR_ID), result.get(0).getMonitorIds());
        assertEquals(Set.of(INDEX_NAME), result.get(0).getIndexToDocData().keySet());
    }

    public void testMultipleDetectors() {
        final String indexName2 = UUID.randomUUID().toString();
        final String workflow2 = UUID.randomUUID().toString();
        final String monitor2 = UUID.randomUUID().toString();
        when(detector2.getInputs()).thenReturn(List.of(detectorInput2));
        when(detectorInput2.getIndices()).thenReturn(List.of(indexName2));
        when(detector2.getWorkflowIds()).thenReturn(List.of(workflow2));
        when(detector2.getMonitorIds()).thenReturn(List.of(monitor2));
        when(detector2.getEnabled()).thenReturn(true);
        when(detector2.isStreamingDetector()).thenReturn(true);

        final Set<String> indexNames = Set.of(INDEX_NAME, indexName2, UUID.randomUUID().toString());
        final List<StreamingDetectorMetadata> result = converter.convert(List.of(detector, detector2), getIndexToDocData(indexNames));
        assertEquals(2, result.size());
        assertEquals(WORKFLOW_ID, result.get(0).getWorkflowId());
        assertEquals(List.of(MONITOR_ID), result.get(0).getMonitorIds());
        assertEquals(Set.of(INDEX_NAME), result.get(0).getIndexToDocData().keySet());
        assertEquals(workflow2, result.get(1).getWorkflowId());
        assertEquals(List.of(monitor2), result.get(1).getMonitorIds());
        assertEquals(Set.of(indexName2), result.get(1).getIndexToDocData().keySet());
    }

    private Map<String, List<DocData>> getIndexToDocData(final Set<String> indexNames) {
        return indexNames.stream().collect(Collectors.toMap(Function.identity(), indexName -> List.of(docData)));
    }
}
