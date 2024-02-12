/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.converters;

import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DocData;
import org.opensearch.securityanalytics.model.StreamingDetectorMetadata;
import org.opensearch.securityanalytics.validators.StreamingDetectorValidators;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class StreamingDetectorMetadataConverter {
    public List<StreamingDetectorMetadata> convert(final List<Detector> detectors, final Map<String, List<DocData>> indexToDocData) {
        return detectors.stream()
                .peek(StreamingDetectorValidators::validateDetector)
                .filter(Detector::isStreamingDetector)
                .filter(detector -> doesDetectorHaveIndexAsInput(detector, indexToDocData.keySet()))
                .map(detector -> createStreamingDetectorMetadata(detector, indexToDocData))
                .collect(Collectors.toList());
    }

    // TODO - some edge cases here since index patterns and IndexRequests directly to a write index are not considered
    private boolean doesDetectorHaveIndexAsInput(final Detector detector, final Set<String> indexNames) {
        final DetectorInput detectorInput = detector.getInputs().get(0);
        return detectorInput.getIndices().stream().anyMatch(indexNames::contains);
    }

    private StreamingDetectorMetadata createStreamingDetectorMetadata(final Detector detector,
                                                                      final Map<String, List<DocData>> indexToDocData) {
        final Map<String, List<DocData>> indexToDocDataForDetectorIndices = getIndexToDocDataForDetectorIndices(
                detector.getInputs().get(0).getIndices(), indexToDocData);

        return new StreamingDetectorMetadata(
                detector.getName(),
                indexToDocDataForDetectorIndices,
                detector.getWorkflowIds().get(0),
                detector.getMonitorIds().get(0)
        );
    }

    private Map<String, List<DocData>> getIndexToDocDataForDetectorIndices(final List<String> detectorIndices,
                                                                           final Map<String, List<DocData>> indexToDocData)  {
        return indexToDocData.entrySet().stream()
                .filter(entry -> detectorIndices.contains(entry.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
