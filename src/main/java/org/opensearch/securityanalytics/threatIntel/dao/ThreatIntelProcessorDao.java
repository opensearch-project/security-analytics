/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.dao;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.opensearch.common.inject.Inject;
import org.opensearch.ingest.IngestMetadata;
import org.opensearch.ingest.IngestService;
import org.opensearch.securityanalytics.threatIntel.processor.ThreatIntelProcessor;

/**
 * Data access object for threat intel processors
 */
public class ThreatIntelProcessorDao {
    private final IngestService ingestService;

    @Inject
    public ThreatIntelProcessorDao(final IngestService ingestService) {
        this.ingestService = ingestService;
    }

    public List<ThreatIntelProcessor> getProcessors(final String datasourceName) {
        IngestMetadata ingestMetadata = ingestService.getClusterService().state().getMetadata().custom(IngestMetadata.TYPE);
        if (ingestMetadata == null) {
            return Collections.emptyList();
        }
        return ingestMetadata.getPipelines()
                .keySet()
                .stream()
                .flatMap(pipelineId -> ingestService.getProcessorsInPipeline(pipelineId, ThreatIntelProcessor.class).stream())
                .filter(threatIntelProcessor -> threatIntelProcessor.getDatasourceName().equals(datasourceName))
                .collect(Collectors.toList());
    }
}
