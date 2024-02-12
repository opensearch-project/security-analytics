/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.converters;

import org.junit.Before;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.securityanalytics.model.DocData;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.test.OpenSearchTestCase;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.mockito.Mockito.when;

public class IndexNameToDocDataConverterTests extends OpenSearchTestCase {
    private static final String INDEX_NAME = UUID.randomUUID().toString();
    private static final String DOC_ID = UUID.randomUUID().toString();

    @Mock
    private BulkRequest bulkRequest;
    @Mock
    private IndexRequest indexRequest;
    @Mock
    private BytesReference indexRequestSource;
    @Mock
    private UpdateRequest updateRequest;
    @Mock
    private IndexRequest updateRequestIndexRequest;
    @Mock
    private BytesReference updateRequestSource;
    @Mock
    private BulkResponse bulkResponse;
    @Mock
    private BulkItemResponse response;

    private IndexNameToDocDataConverter converter;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        converter = new IndexNameToDocDataConverter();

        when(response.getId()).thenReturn(DOC_ID);
        when(indexRequest.index()).thenReturn(INDEX_NAME);
        when(indexRequest.opType()).thenReturn(DocWriteRequest.OpType.INDEX);
        when(indexRequest.source()).thenReturn(indexRequestSource);
        when(updateRequest.index()).thenReturn(INDEX_NAME);
        when(updateRequest.opType()).thenReturn(DocWriteRequest.OpType.UPDATE);
        when(updateRequest.doc()).thenReturn(updateRequestIndexRequest);
        when(updateRequestIndexRequest.source()).thenReturn(updateRequestSource);
    }

    public void testBulkRequestAndResponseLengthsDiffer() {
        when(bulkRequest.requests()).thenReturn(getDocWriteRequestList(1));
        when(bulkResponse.getItems()).thenReturn(getBulkItemResponseArray(2));

        assertThrows(SecurityAnalyticsException.class, () -> converter.convert(bulkRequest, bulkResponse));
    }

    public void testFiltersDeleteOperations() {
        when(bulkRequest.requests()).thenReturn(getDocWriteRequestList(2));
        when(indexRequest.opType()).thenReturn(DocWriteRequest.OpType.DELETE)
                .thenReturn(DocWriteRequest.OpType.INDEX);
        when(bulkResponse.getItems()).thenReturn(getBulkItemResponseArray(2));

        final Map<String, List<DocData>> result = converter.convert(bulkRequest, bulkResponse);
        assertEquals(1, result.size());
        assertTrue(result.containsKey(INDEX_NAME));
        assertEquals(1, result.get(INDEX_NAME).size());
    }

    public void testFiltersFailedBulkItem() {
        when(bulkRequest.requests()).thenReturn(getDocWriteRequestList(2));
        when(bulkResponse.getItems()).thenReturn(getBulkItemResponseArray(2));
        when(response.isFailed()).thenReturn(true)
                .thenReturn(false);

        final Map<String, List<DocData>> result = converter.convert(bulkRequest, bulkResponse);
        assertEquals(1, result.size());
        assertTrue(result.containsKey(INDEX_NAME));
        assertEquals(1, result.get(INDEX_NAME).size());
    }

    public void testCreateOperation() {
        when(bulkRequest.requests()).thenReturn(List.of(indexRequest));
        when(indexRequest.opType()).thenReturn(DocWriteRequest.OpType.CREATE);
        when(bulkResponse.getItems()).thenReturn(getBulkItemResponseArray(1));


        final Map<String, List<DocData>> result = converter.convert(bulkRequest, bulkResponse);
        validateSingleDocSingleIndexCommons(result);
        assertEquals(indexRequestSource, result.get(INDEX_NAME).get(0).getIdDocPair().getDocument());
    }

    public void testIndexOperation() {
        when(bulkRequest.requests()).thenReturn(List.of(indexRequest));
        when(bulkResponse.getItems()).thenReturn(getBulkItemResponseArray(1));

        final Map<String, List<DocData>> result = converter.convert(bulkRequest, bulkResponse);
        validateSingleDocSingleIndexCommons(result);
        assertEquals(indexRequestSource, result.get(INDEX_NAME).get(0).getIdDocPair().getDocument());
    }

    public void testUpdateOperation() {
        when(bulkRequest.requests()).thenReturn(List.of(updateRequest));
        when(bulkResponse.getItems()).thenReturn(getBulkItemResponseArray(1));

        final Map<String, List<DocData>> result = converter.convert(bulkRequest, bulkResponse);
        validateSingleDocSingleIndexCommons(result);
        assertEquals(updateRequestSource, result.get(INDEX_NAME).get(0).getIdDocPair().getDocument());
    }

    public void testMultipleIndicesGenerateUniqueMapEntries() {
        final String secondIndex = UUID.randomUUID().toString();

        when(updateRequest.index()).thenReturn(secondIndex);
        when(bulkRequest.requests()).thenReturn(List.of(indexRequest, updateRequest));
        when(bulkResponse.getItems()).thenReturn(getBulkItemResponseArray(2));

        final Map<String, List<DocData>> result = converter.convert(bulkRequest, bulkResponse);
        assertEquals(2, result.size());
        assertTrue(result.containsKey(INDEX_NAME));
        assertTrue(result.containsKey(secondIndex));
        assertEquals(1, result.get(INDEX_NAME).size());
        assertEquals(indexRequestSource, result.get(INDEX_NAME).get(0).getIdDocPair().getDocument());
        assertEquals(1, result.get(secondIndex).size());
        assertEquals(updateRequestSource, result.get(secondIndex).get(0).getIdDocPair().getDocument());
    }

    public void testMultipleRequestsForSameIndexAddedToMapEntry() {
        when(bulkRequest.requests()).thenReturn(List.of(indexRequest, updateRequest));
        when(bulkResponse.getItems()).thenReturn(getBulkItemResponseArray(2));

        final Map<String, List<DocData>> result = converter.convert(bulkRequest, bulkResponse);
        assertEquals(1, result.size());
        assertTrue(result.containsKey(INDEX_NAME));
        assertEquals(2, result.get(INDEX_NAME).size());
        assertEquals(indexRequestSource, result.get(INDEX_NAME).get(0).getIdDocPair().getDocument());
        assertEquals(updateRequestSource, result.get(INDEX_NAME).get(1).getIdDocPair().getDocument());
    }

    private void validateSingleDocSingleIndexCommons(final Map<String, List<DocData>> result) {
        assertEquals(1, result.size());
        assertTrue(result.containsKey(INDEX_NAME));
        assertEquals(1, result.get(INDEX_NAME).size());
        assertEquals(DOC_ID, result.get(INDEX_NAME).get(0).getIdDocPair().getDocId());
    }

    private List<DocWriteRequest<?>> getDocWriteRequestList(final int length) {
        return IntStream.range(0, length).mapToObj(i -> indexRequest).collect(Collectors.toList());
    }

    private BulkItemResponse[] getBulkItemResponseArray(final int length) {
        return IntStream.range(0, length).mapToObj(i -> response).toArray(BulkItemResponse[]::new);
    }
}
