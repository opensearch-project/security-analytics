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
import org.opensearch.securityanalytics.model.DocData;
import org.opensearch.securityanalytics.model.StreamingDetectorMetadata;
import org.opensearch.test.OpenSearchTestCase;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.IntStream;

public class ExecuteStreamingWorkflowRequestConverterTests extends OpenSearchTestCase {
    private static final String DETECTOR_NAME = UUID.randomUUID().toString();
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
        final Map<String, List<DocData>> indexToDocData = getIndexToDocData(INDEX_NAME, DOC_ID, document);
        final StreamingDetectorMetadata metadata = getStreamingDetectorMetadata(Set.of("field1", "field2"), indexToDocData);

        final ExecuteStreamingWorkflowRequest result = converter.convert(metadata);
        assertEquals(WORKFLOW_ID, result.getWorkflowId());
        assertEquals(1, result.getIndices().size());
        assertEquals(INDEX_NAME, result.getIndices().get(0).getIndex());
        assertEquals(1, result.getIndices().get(0).getIdDocPairs().size());
        assertEquals(DOC_ID, result.getIndices().get(0).getIdDocPairs().get(0).getDocId());
        assertEquals(document, result.getIndices().get(0).getIdDocPairs().get(0).getDocument());
    }

    public void testFiltersDocFields() {
        final BytesReference document = getDocument(DOCUMENT_STRING);
        final Map<String, List<DocData>> indexToDocData = getIndexToDocData(INDEX_NAME, DOC_ID, document);
        final StreamingDetectorMetadata metadata = getStreamingDetectorMetadata(Set.of("field1"), indexToDocData);

        final ExecuteStreamingWorkflowRequest result = converter.convert(metadata);
        assertEquals(WORKFLOW_ID, result.getWorkflowId());
        assertEquals(1, result.getIndices().size());
        assertEquals(INDEX_NAME, result.getIndices().get(0).getIndex());
        assertEquals(1, result.getIndices().get(0).getIdDocPairs().size());
        assertEquals(DOC_ID, result.getIndices().get(0).getIdDocPairs().get(0).getDocId());

        final BytesReference filteredDocument = getDocument("{\"field1\":\"value1\"}");
        assertEquals(filteredDocument, result.getIndices().get(0).getIdDocPairs().get(0).getDocument());
    }

    public void testInvalidDocumentThrowsParsingException() {
        final BytesReference document = getDocument("invalid doc");
        final Map<String, List<DocData>> indexToDocData = getIndexToDocData(INDEX_NAME, DOC_ID, document);
        final  StreamingDetectorMetadata metadata = getStreamingDetectorMetadata(Set.of("field1"), indexToDocData);

        assertThrows(MapperParsingException.class, () -> converter.convert(metadata));
    }

    public void testMultipleDocs() {
        final String secondDocId = UUID.randomUUID().toString();
        final String secondDocument = "{\"field1\":\"abcdef\",\"field2\":\"value2\"}";
        final Map<String, List<DocData>> indexToDocData = Map.of(
                INDEX_NAME,
                List.of(
                        new DocData(new IdDocPair(DOC_ID, getDocument(DOCUMENT_STRING)), 0),
                        new DocData(new IdDocPair(secondDocId, getDocument(secondDocument)), 0)
                )
        );
        final StreamingDetectorMetadata metadata = getStreamingDetectorMetadata(Set.of("field1"), indexToDocData);

        final ExecuteStreamingWorkflowRequest result = converter.convert(metadata);
        assertEquals(WORKFLOW_ID, result.getWorkflowId());
        assertEquals(1, result.getIndices().size());
        assertEquals(INDEX_NAME, result.getIndices().get(0).getIndex());
        assertEquals(2, result.getIndices().get(0).getIdDocPairs().size());
        assertEquals(DOC_ID, result.getIndices().get(0).getIdDocPairs().get(0).getDocId());
        assertEquals(secondDocId, result.getIndices().get(0).getIdDocPairs().get(1).getDocId());

        final BytesReference filteredDocument1 = getDocument("{\"field1\":\"value1\"}");
        assertEquals(filteredDocument1, result.getIndices().get(0).getIdDocPairs().get(0).getDocument());
        final BytesReference filteredDocument2 = getDocument("{\"field1\":\"abcdef\"}");
        assertEquals(filteredDocument2, result.getIndices().get(0).getIdDocPairs().get(1).getDocument());
    }

    public void testMultipleIndices() {
        final String secondIndexName = UUID.randomUUID().toString();
        final String secondDocId = UUID.randomUUID().toString();
        final String secondDocument = "{\"field1\":\"abcdef\",\"field2\":\"value2\"}";
        final Map<String, List<DocData>> indexToDocData = Map.of(
                INDEX_NAME,
                List.of(new DocData(new IdDocPair(DOC_ID, getDocument(DOCUMENT_STRING)), 0)),
                secondIndexName,
                List.of(new DocData(new IdDocPair(secondDocId, getDocument(secondDocument)), 0))
        );
        final StreamingDetectorMetadata metadata = getStreamingDetectorMetadata(Set.of("field1"), indexToDocData);

        final ExecuteStreamingWorkflowRequest result = converter.convert(metadata);
        assertEquals(WORKFLOW_ID, result.getWorkflowId());
        assertEquals(2, result.getIndices().size());

        final int indicesListIndex = IntStream.range(0, result.getIndices().size())
                .filter(i -> INDEX_NAME.equals(result.getIndices().get(i).getIndex()))
                .findFirst().orElse(-1);
        assertEquals(INDEX_NAME, result.getIndices().get(indicesListIndex).getIndex());
        assertEquals(1, result.getIndices().get(indicesListIndex).getIdDocPairs().size());
        assertEquals(DOC_ID, result.getIndices().get(indicesListIndex).getIdDocPairs().get(0).getDocId());
        final BytesReference filteredDocument1 = getDocument("{\"field1\":\"value1\"}");
        assertEquals(filteredDocument1, result.getIndices().get(indicesListIndex).getIdDocPairs().get(0).getDocument());

        final int otherIndicesListIndex = indicesListIndex == 0 ? 1 : 0;
        assertEquals(secondIndexName, result.getIndices().get(otherIndicesListIndex).getIndex());
        assertEquals(1, result.getIndices().get(otherIndicesListIndex).getIdDocPairs().size());
        assertEquals(secondDocId, result.getIndices().get(otherIndicesListIndex).getIdDocPairs().get(0).getDocId());
        final BytesReference filteredDocument2 = getDocument("{\"field1\":\"abcdef\"}");
        assertEquals(filteredDocument2, result.getIndices().get(otherIndicesListIndex).getIdDocPairs().get(0).getDocument());
    }

    private StreamingDetectorMetadata getStreamingDetectorMetadata(final Set<String> queryFields, final Map<String, List<DocData>> indexToDocData) {
        final StreamingDetectorMetadata metadata = new StreamingDetectorMetadata(DETECTOR_NAME, indexToDocData, WORKFLOW_ID, null);
        metadata.addQueryFields(queryFields);

        return metadata;
    }

    private Map<String, List<DocData>> getIndexToDocData(final String indexName, final String docId, final BytesReference document) {
        return Map.of(indexName, List.of(new DocData(new IdDocPair(docId, document), 0)));
    }

    private BytesReference getDocument(final String docString) {
        return BytesReference.fromByteBuffer(ByteBuffer.wrap(docString.getBytes(StandardCharsets.UTF_8)));
    }
}
