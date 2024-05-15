//package org.opensearch.securityanalytics.index;
//
//import org.junit.jupiter.api.AfterEach;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.mockito.ArgumentCaptor;
//import org.mockito.Mock;
//import org.mockito.MockitoAnnotations;
//import org.opensearch.OpenSearchStatusException;
//import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
//import org.opensearch.action.bulk.BulkRequest;
//import org.opensearch.action.bulk.BulkResponse;
//import org.opensearch.client.IndicesClient;
//import org.opensearch.client.RequestOptions;
//import org.opensearch.client.RestHighLevelClient;
//import org.opensearch.client.indices.CreateIndexRequest;
//import org.opensearch.client.indices.CreateIndexResponse;
//import org.opensearch.common.settings.Settings;
//import org.opensearch.core.rest.RestStatus;
//import org.opensearch.index.query.QueryBuilder;
//import org.opensearch.index.reindex.BulkByScrollResponse;
//import org.opensearch.index.reindex.DeleteByQueryRequest;
//import org.opensearch.securityanalytics.exceptions.IndexAccessorException;
//
//import java.io.IOException;
//import java.util.UUID;
//
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import static org.junit.jupiter.api.Assertions.assertThrows;
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.ArgumentMatchers.eq;
//import static org.mockito.Mockito.verify;
//import static org.mockito.Mockito.verifyNoMoreInteractions;
//import static org.mockito.Mockito.when;
//
//public class RHLCIndexAccessorTests {
//    private static final String INDEX = UUID.randomUUID().toString();
//
//    @Mock
//    private RestHighLevelClient client;
//    @Mock
//    private IndicesClient indicesClient;
//    @Mock
//    private CreateIndexResponse createIndexResponse;
//    @Mock
//    private DeleteByQueryRequest deleteByQueryRequest;
//    @Mock
//    private BulkByScrollResponse bulkByScrollResponse;
//    @Mock
//    private BulkRequest bulkRequest;
//    @Mock
//    private BulkResponse bulkResponse;
//    @Mock
//    private Settings settings;
//    @Mock
//    private QueryBuilder queryBuilder;
//
//    private RHLCIndexAccessor rhlcIndexAccessor;
//
//    @BeforeEach
//    public void setup() {
//        MockitoAnnotations.openMocks(this);
//        rhlcIndexAccessor = new RHLCIndexAccessor(client);
//    }
//
//    @AfterEach
//    public void teardown() {
//        verifyNoMoreInteractions(client, indicesClient, createIndexResponse, deleteByQueryRequest, bulkByScrollResponse,
//                bulkRequest, bulkResponse, settings, queryBuilder);
//    }
//
//    @Test
//    public void testCreateIndex() throws IOException {
//        when(client.indices()).thenReturn(indicesClient);
//
//        rhlcIndexAccessor.createRolloverAlias(INDEX, settings);
//
//        verify(client).indices();
//        final ArgumentCaptor<CreateIndexRequest> captor = ArgumentCaptor.forClass(CreateIndexRequest.class);
//        verify(indicesClient).create(captor.capture(), eq(RequestOptions.DEFAULT));
//        assertEquals(INDEX, captor.getValue().index());
//        assertEquals(settings, captor.getValue().settings());
//    }
//
//    @Test
//    public void testCreateIndex_ExceptionCreatingIndex() throws IOException {
//        when(client.indices()).thenReturn(indicesClient);
//        when(indicesClient.create(any(CreateIndexRequest.class), eq(RequestOptions.DEFAULT))).thenThrow(new RuntimeException());
//
//        assertThrows(IndexAccessorException.class, () -> rhlcIndexAccessor.createRolloverAlias(INDEX, settings));
//
//        verify(client).indices();
//        final ArgumentCaptor<CreateIndexRequest> captor = ArgumentCaptor.forClass(CreateIndexRequest.class);
//        verify(indicesClient).create(captor.capture(), eq(RequestOptions.DEFAULT));
//        assertEquals(INDEX, captor.getValue().index());
//        assertEquals(settings, captor.getValue().settings());
//    }
//
//    @Test
//    public void testDeleteIndex() throws IOException {
//        when(client.indices()).thenReturn(indicesClient);
//
//        rhlcIndexAccessor.deleteIndex(INDEX);
//
//        verify(client).indices();
//        final ArgumentCaptor<DeleteIndexRequest> captor = ArgumentCaptor.forClass(DeleteIndexRequest.class);
//        verify(indicesClient).delete(captor.capture(), eq(RequestOptions.DEFAULT));
//        assertEquals(1, captor.getValue().indices().length);
//        assertEquals(INDEX, captor.getValue().indices()[0]);
//    }
//
//    @Test
//    public void testDeleteIndex_IndexDoesNotExist() throws IOException {
//        when(client.indices()).thenReturn(indicesClient);
//        when(indicesClient.delete(any(DeleteIndexRequest.class), eq(RequestOptions.DEFAULT)))
//                .thenThrow(new OpenSearchStatusException("index_not_found_exception", RestStatus.NOT_FOUND));
//
//        rhlcIndexAccessor.deleteIndex(INDEX);
//
//        verify(client).indices();
//        final ArgumentCaptor<DeleteIndexRequest> captor = ArgumentCaptor.forClass(DeleteIndexRequest.class);
//        verify(indicesClient).delete(captor.capture(), eq(RequestOptions.DEFAULT));
//        assertEquals(1, captor.getValue().indices().length);
//        assertEquals(INDEX, captor.getValue().indices()[0]);
//    }
//
//    @Test
//    public void testDeleteIndex_ExceptionDeletingIndex() throws IOException {
//        when(client.indices()).thenReturn(indicesClient);
//        when(indicesClient.delete(any(DeleteIndexRequest.class), eq(RequestOptions.DEFAULT))).thenThrow(new RuntimeException());
//
//        assertThrows(IndexAccessorException.class, () -> rhlcIndexAccessor.deleteIndex(INDEX));
//
//        verify(client).indices();
//        final ArgumentCaptor<DeleteIndexRequest> captor = ArgumentCaptor.forClass(DeleteIndexRequest.class);
//        verify(indicesClient).delete(captor.capture(), eq(RequestOptions.DEFAULT));
//        assertEquals(1, captor.getValue().indices().length);
//        assertEquals(INDEX, captor.getValue().indices()[0]);
//    }
//
//    @Test
//    public void testDeleteByQuery() throws IOException {
//        when(client.deleteByQuery(any(DeleteByQueryRequest.class), eq(RequestOptions.DEFAULT))).thenReturn(bulkByScrollResponse);
//
//        final BulkByScrollResponse result = rhlcIndexAccessor.deleteByQuery(INDEX, queryBuilder);
//        assertEquals(bulkByScrollResponse, result);
//
//        verify(client).deleteByQuery(eq(deleteByQueryRequest), eq(RequestOptions.DEFAULT));
//    }
//
//    @Test
//    public void testDeleteByQuery_ExceptionDeletingByQuery() throws IOException {
//        when(client.deleteByQuery(any(DeleteByQueryRequest.class), eq(RequestOptions.DEFAULT))).thenThrow(new RuntimeException());
//        when(deleteByQueryRequest.indices()).thenReturn(new String[] { INDEX });
//
//        assertThrows(IndexAccessorException.class, () -> rhlcIndexAccessor.deleteByQuery(INDEX, queryBuilder));
//
//        verify(client).deleteByQuery(eq(deleteByQueryRequest), eq(RequestOptions.DEFAULT));
//        verify(deleteByQueryRequest).indices();
//    }
//
//    @Test
//    public void testBulk() throws IOException {
//        when(client.bulk(eq(bulkRequest), eq(RequestOptions.DEFAULT))).thenReturn(bulkResponse);
//
//        final BulkResponse result = rhlcIndexAccessor.bulk(bulkRequest);
//        assertEquals(bulkResponse, result);
//
//        verify(client).bulk(eq(bulkRequest), eq(RequestOptions.DEFAULT));
//    }
//
//    @Test
//    public void testBulk_ExceptionBulking() throws IOException {
//        when(client.bulk(eq(bulkRequest), eq(RequestOptions.DEFAULT))).thenThrow(new RuntimeException());
//
//        assertThrows(IndexAccessorException.class, () -> rhlcIndexAccessor.bulk(bulkRequest));
//
//        verify(client).bulk(eq(bulkRequest), eq(RequestOptions.DEFAULT));
//    }
//}
