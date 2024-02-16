/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class StreamingDetectorMetadata {
    private final String detectorName;
    private final Map<String, List<DocData>> indexToDocData;
    private final String workflowId;
    private final List<String> monitorIds;
    private final Set<String> queryFields;

    public StreamingDetectorMetadata(final String detectorName, final Map<String, List<DocData>> indexToDocData,
                                     final String workflowId, final List<String> monitorIds) {
        this.detectorName = detectorName;
        this.indexToDocData = indexToDocData;
        this.workflowId = workflowId;
        this.monitorIds = monitorIds;
        this.queryFields = new HashSet<>();
    }

    public String getDetectorName() {
        return detectorName;
    }

    public Map<String, List<DocData>> getIndexToDocData() {
        return indexToDocData;
    }

    public String getWorkflowId() {
        return workflowId;
    }

    public List<String> getMonitorIds() {
        return monitorIds;
    }

    public Set<String> getQueryFields() {
        return queryFields;
    }

    public void addQueryFields(final Set<String> queryFieldsToAdd) {
        queryFields.addAll(queryFieldsToAdd);
    }
}
