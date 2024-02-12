/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.converters;

import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.commons.alerting.action.ExecuteStreamingWorkflowRequest;
import org.opensearch.commons.alerting.model.IdDocPair;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.mapper.MapperParsingException;
import org.opensearch.securityanalytics.model.StreamingDetectorMetadata;
import org.opensearch.test.OpenSearchTestCase;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.IntStream;

public class ExecuteStreamingWorkflowRequestConverterTests extends OpenSearchTestCase {
    private static final String INDEX_NAME = UUID.randomUUID().toString();
    private static final String DOC_ID = UUID.randomUUID().toString();
    private static final String DOCUMENT_STRING = "{\"field1\":\"value1\",\"field2\":\"value2\"}";
    private static final String WORKFLOW_ID = UUID.randomUUID().toString();

    @Mock
    private NamedXContentRegistry xContentRegistry;

    private ExecuteStreamingWorkflowRequestConverter converter;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        converter = new ExecuteStreamingWorkflowRequestConverter(xContentRegistry);
    }

    public void testSingleDetectorSingleIndexSingleDocNoFiltering() {
        final BytesReference document = getDocument(DOCUMENT_STRING);
        final Map<String, List<IdDocPair>> indexToDocIdPairs = getIndexToIdDocPairs(document);
        final Collection<StreamingDetectorMetadata> metadata = List.of(getStreamingDetectorMetadata(Set.of("field1", "field2")));

        final List<ExecuteStreamingWorkflowRequest> result = converter.convert(metadata, indexToDocIdPairs);
        assertEquals(1, result.size());
        assertEquals(WORKFLOW_ID, result.get(0).getWorkflowId());
        assertEquals(1, result.get(0).getIndices().size());
        assertEquals(INDEX_NAME, result.get(0).getIndices().get(0).getIndex());
        assertEquals(1, result.get(0).getIndices().get(0).getIdDocPairs().size());
        assertEquals(DOC_ID, result.get(0).getIndices().get(0).getIdDocPairs().get(0).getDocId());
        assertEquals(document, result.get(0).getIndices().get(0).getIdDocPairs().get(0).getDocument());
    }

    public void testFiltersDocFields() {
        final Map<String, List<IdDocPair>> indexToDocIdPairs = getIndexToIdDocPairs(getDocument(DOCUMENT_STRING));
        final Collection<StreamingDetectorMetadata> metadata = List.of(getStreamingDetectorMetadata(Set.of("field1")));

        final List<ExecuteStreamingWorkflowRequest> result = converter.convert(metadata, indexToDocIdPairs);
        assertEquals(1, result.size());
        assertEquals(WORKFLOW_ID, result.get(0).getWorkflowId());
        assertEquals(1, result.get(0).getIndices().size());
        assertEquals(INDEX_NAME, result.get(0).getIndices().get(0).getIndex());
        assertEquals(1, result.get(0).getIndices().get(0).getIdDocPairs().size());
        assertEquals(DOC_ID, result.get(0).getIndices().get(0).getIdDocPairs().get(0).getDocId());

        final BytesReference filteredDocument = getDocument("{\"field1\":\"value1\"}");
        assertEquals(filteredDocument, result.get(0).getIndices().get(0).getIdDocPairs().get(0).getDocument());
    }

    public void testInvalidDocumentThrowsParsingException() {
        final Map<String, List<IdDocPair>> indexToDocIdPairs = getIndexToIdDocPairs(getDocument("invalid doc"));
        final Collection<StreamingDetectorMetadata> metadata = List.of(getStreamingDetectorMetadata(Set.of("field1")));

        assertThrows(MapperParsingException.class, () -> converter.convert(metadata, indexToDocIdPairs));
    }

    public void testFiltersIndicesNotPartOfDetector() {
        final BytesReference document = getDocument(DOCUMENT_STRING);
        final Map<String, List<IdDocPair>> indexToDocIdPairs = new HashMap<>();
        indexToDocIdPairs.put(INDEX_NAME, List.of(new IdDocPair(DOC_ID, document)));
        indexToDocIdPairs.put(UUID.randomUUID().toString(), List.of(new IdDocPair(DOC_ID, document)));
        final Collection<StreamingDetectorMetadata> metadata = List.of(getStreamingDetectorMetadata(Set.of("field1", "field2")));

        final List<ExecuteStreamingWorkflowRequest> result = converter.convert(metadata, indexToDocIdPairs);
        assertEquals(1, result.size());
        assertEquals(WORKFLOW_ID, result.get(0).getWorkflowId());
        assertEquals(1, result.get(0).getIndices().size());
        assertEquals(INDEX_NAME, result.get(0).getIndices().get(0).getIndex());
        assertEquals(1, result.get(0).getIndices().get(0).getIdDocPairs().size());
        assertEquals(DOC_ID, result.get(0).getIndices().get(0).getIdDocPairs().get(0).getDocId());
        assertEquals(document, result.get(0).getIndices().get(0).getIdDocPairs().get(0).getDocument());
    }

    public void testMultipleDocs() {
        final String secondDocId = UUID.randomUUID().toString();
        final String secondDocument = "{\"field1\":\"abcdef\",\"field2\":\"value2\"}";
        final Map<String, List<IdDocPair>> indexToDocIdPairs = Map.of(
                INDEX_NAME,
                List.of(new IdDocPair(DOC_ID, getDocument(DOCUMENT_STRING)), new IdDocPair(secondDocId, getDocument(secondDocument)))
        );
        final Collection<StreamingDetectorMetadata> metadata = List.of(getStreamingDetectorMetadata(Set.of("field1")));

        final List<ExecuteStreamingWorkflowRequest> result = converter.convert(metadata, indexToDocIdPairs);
        assertEquals(1, result.size());
        assertEquals(WORKFLOW_ID, result.get(0).getWorkflowId());
        assertEquals(1, result.get(0).getIndices().size());
        assertEquals(INDEX_NAME, result.get(0).getIndices().get(0).getIndex());
        assertEquals(2, result.get(0).getIndices().get(0).getIdDocPairs().size());
        assertEquals(DOC_ID, result.get(0).getIndices().get(0).getIdDocPairs().get(0).getDocId());
        assertEquals(secondDocId, result.get(0).getIndices().get(0).getIdDocPairs().get(1).getDocId());

        final BytesReference filteredDocument1 = getDocument("{\"field1\":\"value1\"}");
        assertEquals(filteredDocument1, result.get(0).getIndices().get(0).getIdDocPairs().get(0).getDocument());
        final BytesReference filteredDocument2 = getDocument("{\"field1\":\"abcdef\"}");
        assertEquals(filteredDocument2, result.get(0).getIndices().get(0).getIdDocPairs().get(1).getDocument());
    }

    public void testMultipleIndices() {
        final String secondIndexName = UUID.randomUUID().toString();
        final String secondDocId = UUID.randomUUID().toString();
        final String secondDocument = "{\"field1\":\"abcdef\",\"field2\":\"value2\"}";
        final Map<String, List<IdDocPair>> indexToDocIdPairs = Map.of(
                INDEX_NAME,
                List.of(new IdDocPair(DOC_ID, getDocument(DOCUMENT_STRING))),
                secondIndexName,
                List.of(new IdDocPair(secondDocId, getDocument(secondDocument)))
        );
        final StreamingDetectorMetadata metadata = new StreamingDetectorMetadata(List.of(INDEX_NAME, secondIndexName), WORKFLOW_ID, null);
        metadata.addQueryFields(Set.of("field1"));

        final List<ExecuteStreamingWorkflowRequest> result = converter.convert(List.of(metadata), indexToDocIdPairs);
        assertEquals(1, result.size());
        assertEquals(WORKFLOW_ID, result.get(0).getWorkflowId());
        assertEquals(2, result.get(0).getIndices().size());
        assertEquals(INDEX_NAME, result.get(0).getIndices().get(0).getIndex());
        assertEquals(1, result.get(0).getIndices().get(0).getIdDocPairs().size());
        assertEquals(DOC_ID, result.get(0).getIndices().get(0).getIdDocPairs().get(0).getDocId());
        final BytesReference filteredDocument1 = getDocument("{\"field1\":\"value1\"}");
        assertEquals(filteredDocument1, result.get(0).getIndices().get(0).getIdDocPairs().get(0).getDocument());

        assertEquals(secondIndexName, result.get(0).getIndices().get(1).getIndex());
        assertEquals(1, result.get(0).getIndices().get(1).getIdDocPairs().size());
        assertEquals(secondDocId, result.get(0).getIndices().get(1).getIdDocPairs().get(0).getDocId());
        final BytesReference filteredDocument2 = getDocument("{\"field1\":\"abcdef\"}");
        assertEquals(filteredDocument2, result.get(0).getIndices().get(1).getIdDocPairs().get(0).getDocument());
    }

    public void testMultipleWorkflow() {
        final BytesReference document = getDocument(DOCUMENT_STRING);
        final Map<String, List<IdDocPair>> indexToDocIdPairs = getIndexToIdDocPairs(document);

        final String workflowId2 = UUID.randomUUID().toString();
        final StreamingDetectorMetadata metadata1 = new StreamingDetectorMetadata(List.of(INDEX_NAME), WORKFLOW_ID, null);
        metadata1.addQueryFields(Set.of("field1", "field2"));
        final StreamingDetectorMetadata metadata2 = new StreamingDetectorMetadata(List.of(INDEX_NAME), workflowId2, null);
        metadata2.addQueryFields(Set.of("field1"));

        final List<ExecuteStreamingWorkflowRequest> result = converter.convert(List.of(metadata1, metadata2), indexToDocIdPairs);
        assertEquals(2, result.size());
        assertEquals(WORKFLOW_ID, result.get(0).getWorkflowId());
        assertEquals(workflowId2, result.get(1).getWorkflowId());

        IntStream.range(0, 2).forEach(i -> {
            assertEquals(1, result.get(i).getIndices().size());
            assertEquals(INDEX_NAME, result.get(i).getIndices().get(0).getIndex());
            assertEquals(1, result.get(i).getIndices().get(0).getIdDocPairs().size());
            assertEquals(DOC_ID, result.get(i).getIndices().get(0).getIdDocPairs().get(0).getDocId());
        });

        assertEquals(document, result.get(0).getIndices().get(0).getIdDocPairs().get(0).getDocument());
        final BytesReference filteredDocument = getDocument("{\"field1\":\"value1\"}");
        assertEquals(filteredDocument, result.get(1).getIndices().get(0).getIdDocPairs().get(0).getDocument());
    }

    private Map<String, List<IdDocPair>> getIndexToIdDocPairs(final BytesReference document) {
        return Map.of(INDEX_NAME, List.of(new IdDocPair(DOC_ID, document)));
    }

    private StreamingDetectorMetadata getStreamingDetectorMetadata(final Set<String> queryFields) {
        final StreamingDetectorMetadata metadata = new StreamingDetectorMetadata(List.of(INDEX_NAME), WORKFLOW_ID, null);
        metadata.addQueryFields(queryFields);

        return metadata;
    }

    private BytesReference getDocument(final String docString) {
        return BytesReference.fromByteBuffer(ByteBuffer.wrap(docString.getBytes(StandardCharsets.UTF_8)));
    }
}
