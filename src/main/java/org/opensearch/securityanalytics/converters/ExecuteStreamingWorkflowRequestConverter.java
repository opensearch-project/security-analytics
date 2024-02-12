/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.converters;

import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.xcontent.support.XContentMapValues;
import org.opensearch.commons.alerting.action.ExecuteStreamingWorkflowRequest;
import org.opensearch.commons.alerting.model.IdDocPair;
import org.opensearch.commons.alerting.model.StreamingIndex;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.mapper.MapperParsingException;
import org.opensearch.securityanalytics.model.DocData;
import org.opensearch.securityanalytics.model.StreamingDetectorMetadata;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ExecuteStreamingWorkflowRequestConverter {
    private final NamedXContentRegistry xContentRegistry;

    @Inject
    public ExecuteStreamingWorkflowRequestConverter(final NamedXContentRegistry xContentRegistry) {
        this.xContentRegistry = xContentRegistry;
    }

    public ExecuteStreamingWorkflowRequest convert(final StreamingDetectorMetadata streamingDetectorMetadata) {
        final List<StreamingIndex> streamingIndices = streamingDetectorMetadata.getIndexToDocData().entrySet().stream()
                .map(entry -> createStreamingIndex(entry, streamingDetectorMetadata.getQueryFields()))
                .collect(Collectors.toList());

        return new ExecuteStreamingWorkflowRequest(streamingDetectorMetadata.getWorkflowId(), streamingIndices);
    }

    private StreamingIndex createStreamingIndex(final Map.Entry<String, List<DocData>> indexToDocData, final Set<String> fieldNames) {
        final List<IdDocPair> filteredIdDocPairs = getFilteredIdDocPairs(indexToDocData.getValue(), fieldNames);
        return new StreamingIndex(indexToDocData.getKey(), filteredIdDocPairs);
    }

    private List<IdDocPair> getFilteredIdDocPairs(final List<DocData> indexToDocData, final Set<String> fieldNames) {
        return indexToDocData.stream()
                .map(DocData::getIdDocPair)
                .map(idDocPair -> {
                    final String docId = idDocPair.getDocId();
                    final BytesReference filteredDocument = getFilteredDocument(idDocPair.getDocument(), fieldNames);
                    return new IdDocPair(docId, filteredDocument);
                })
                .collect(Collectors.toList());
    }

    // TODO - this logic is consuming ~40% of the CPU. Is there a more efficient way to filter the docs?
    private BytesReference getFilteredDocument(final BytesReference document, final Set<String> fieldNames) {
        try {
            final XContentParser xcp = XContentType.JSON.xContent().createParser(
                    xContentRegistry, LoggingDeprecationHandler.INSTANCE, document.streamInput());
            final Map<String, ?> documentAsMap = xcp.map();
            final Map<String, Object> filteredDocumentAsMap = XContentMapValues.filter(documentAsMap, fieldNames.toArray(String[]::new), new String[0]);

            final XContentBuilder builder = XContentFactory.jsonBuilder();
            builder.map(filteredDocumentAsMap);
            return BytesReference.bytes(builder);
        } catch (final Exception e) {
            throw new MapperParsingException("Exception parsing document to map", e);
        }
    }
}
