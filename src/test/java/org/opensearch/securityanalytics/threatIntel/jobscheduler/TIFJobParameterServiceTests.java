/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;

import org.apache.lucene.search.TotalHits;
import org.junit.Before;
import org.mockito.ArgumentCaptor;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.common.Randomness;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestHelper;

public class TIFJobParameterServiceTests extends ThreatIntelTestCase {
    private TIFJobParameterService tifJobParameterService;

    @Before
    public void init() {
        tifJobParameterService = new TIFJobParameterService(verifyingClient, clusterService);
    }

    public void testCreateIndexIfNotExists_whenIndexExist_thenCreateRequestIsNotCalled() {
        when(metadata.hasIndex(TIFJobExtension.JOB_INDEX_NAME)).thenReturn(true);

        // Verify
        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> { throw new RuntimeException("Shouldn't get called"); });

        // Run
        StepListener<Void> stepListener = new StepListener<>();
        tifJobParameterService.createIndexIfNotExists(stepListener);

        // Verify stepListener is called
        stepListener.result();
    }

    public void testCreateIndexIfNotExists_whenIndexExist_thenCreateRequestIsCalled() {
        when(metadata.hasIndex(TIFJobExtension.JOB_INDEX_NAME)).thenReturn(false);

        // Verify
        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            assertTrue(actionRequest instanceof CreateIndexRequest);
            CreateIndexRequest request = (CreateIndexRequest) actionRequest;
            assertEquals(TIFJobExtension.JOB_INDEX_NAME, request.index());
            assertEquals("1", request.settings().get("index.number_of_shards"));
            assertEquals("0-all", request.settings().get("index.auto_expand_replicas"));
            assertEquals("true", request.settings().get("index.hidden"));
            assertNotNull(request.mappings());
            return null;
        });

        // Run
        StepListener<Void> stepListener = new StepListener<>();
        tifJobParameterService.createIndexIfNotExists(stepListener);

        // Verify stepListener is called
        stepListener.result();
    }

    public void testCreateIndexIfNotExists_whenIndexCreatedAlready_thenExceptionIsIgnored() {
        when(metadata.hasIndex(TIFJobExtension.JOB_INDEX_NAME)).thenReturn(false);
        verifyingClient.setExecuteVerifier(
                (actionResponse, actionRequest) -> { throw new ResourceAlreadyExistsException(TIFJobExtension.JOB_INDEX_NAME); }
        );

        // Run
        StepListener<Void> stepListener = new StepListener<>();
        tifJobParameterService.createIndexIfNotExists(stepListener);

        // Verify stepListener is called
        stepListener.result();
    }

    public void testCreateIndexIfNotExists_whenExceptionIsThrown_thenExceptionIsThrown() {
        when(metadata.hasIndex(TIFJobExtension.JOB_INDEX_NAME)).thenReturn(false);
        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> { throw new RuntimeException(); });

        // Run
        StepListener<Void> stepListener = new StepListener<>();
        tifJobParameterService.createIndexIfNotExists(stepListener);

        // Verify stepListener is called
        expectThrows(RuntimeException.class, () -> stepListener.result());
    }

    public void testUpdateTIFJobParameter_whenValidInput_thenSucceed() throws Exception {
        String tifJobName = ThreatIntelTestHelper.randomLowerCaseString();
        TIFJobParameter tifJobParameter = new TIFJobParameter(
                tifJobName,
                new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS)
        );
        Instant previousTime = Instant.now().minusMillis(1);
        tifJobParameter.setLastUpdateTime(previousTime);

        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            assertTrue(actionRequest instanceof IndexRequest);
            IndexRequest request = (IndexRequest) actionRequest;
            assertEquals(tifJobParameter.getName(), request.id());
            assertEquals(DocWriteRequest.OpType.INDEX, request.opType());
            assertEquals(TIFJobExtension.JOB_INDEX_NAME, request.index());
            assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, request.getRefreshPolicy());
            return null;
        });

        tifJobParameterService.updateJobSchedulerParameter(tifJobParameter);
        assertTrue(previousTime.isBefore(tifJobParameter.getLastUpdateTime()));
    }

    public void testPutTifJobParameter_whenValidInput_thenSucceed() {
        TIFJobParameter tifJobParameter = randomTifJobParameter();
        Instant previousTime = Instant.now().minusMillis(1);
        tifJobParameter.setLastUpdateTime(previousTime);

        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            assertTrue(actionRequest instanceof IndexRequest);
            IndexRequest indexRequest = (IndexRequest) actionRequest;
            assertEquals(TIFJobExtension.JOB_INDEX_NAME, indexRequest.index());
            assertEquals(tifJobParameter.getName(), indexRequest.id());
            assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, indexRequest.getRefreshPolicy());
            assertEquals(DocWriteRequest.OpType.CREATE, indexRequest.opType());
            return null;
        });

        tifJobParameterService.putTIFJobParameter(tifJobParameter, mock(ActionListener.class));
        assertTrue(previousTime.isBefore(tifJobParameter.getLastUpdateTime()));
    }

    public void testGetTifJobParameter_whenException_thenNull() throws Exception {
        TIFJobParameter tifJobParameter = setupClientForGetRequest(true, new IndexNotFoundException(TIFJobExtension.JOB_INDEX_NAME));
        assertNull(tifJobParameterService.getJobParameter(tifJobParameter.getName()));
    }

    public void testGetTifJobParameter_whenExist_thenReturnTifJobParameter() throws Exception {
        TIFJobParameter tifJobParameter = setupClientForGetRequest(true, null);
        assertEquals(tifJobParameter, tifJobParameterService.getJobParameter(tifJobParameter.getName()));
    }

    public void testGetTifJobParameter_whenNotExist_thenNull() throws Exception {
        TIFJobParameter tifJobParameter = setupClientForGetRequest(false, null);
        assertNull(tifJobParameterService.getJobParameter(tifJobParameter.getName()));
    }

    public void testGetTifJobParameter_whenExistWithListener_thenListenerIsCalledWithTifJobParameter() {
        TIFJobParameter tifJobParameter = setupClientForGetRequest(true, null);
        ActionListener<TIFJobParameter> listener = mock(ActionListener.class);
        tifJobParameterService.getJobParameter(tifJobParameter.getName(), listener);
        verify(listener).onResponse(eq(tifJobParameter));
    }

    public void testGetTifJobParameter_whenNotExistWithListener_thenListenerIsCalledWithNull() {
        TIFJobParameter tifJobParameter = setupClientForGetRequest(false, null);
        ActionListener<TIFJobParameter> listener = mock(ActionListener.class);
        tifJobParameterService.getJobParameter(tifJobParameter.getName(), listener);
        verify(listener).onResponse(null);
    }

    private TIFJobParameter setupClientForGetRequest(final boolean isExist, final RuntimeException exception) {
        TIFJobParameter tifJobParameter = randomTifJobParameter();

        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            assertTrue(actionRequest instanceof GetRequest);
            GetRequest request = (GetRequest) actionRequest;
            assertEquals(tifJobParameter.getName(), request.id());
            assertEquals(TIFJobExtension.JOB_INDEX_NAME, request.index());
            GetResponse response = getMockedGetResponse(isExist ? tifJobParameter : null);
            if (exception != null) {
                throw exception;
            }
            return response;
        });
        return tifJobParameter;
    }

    public void testDeleteTifJobParameter_whenValidInput_thenSucceed() {
        TIFJobParameter tifJobParameter = randomTifJobParameter();
        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            // Verify
            assertTrue(actionRequest instanceof DeleteRequest);
            DeleteRequest request = (DeleteRequest) actionRequest;
            assertEquals(TIFJobExtension.JOB_INDEX_NAME, request.index());
            assertEquals(DocWriteRequest.OpType.DELETE, request.opType());
            assertEquals(tifJobParameter.getName(), request.id());
            assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, request.getRefreshPolicy());

            DeleteResponse response = mock(DeleteResponse.class);
            when(response.status()).thenReturn(RestStatus.OK);
            return response;
        });

        // Run
        tifJobParameterService.deleteTIFJobParameter(tifJobParameter);
    }

    public void testDeleteTifJobParameter_whenIndexNotFound_thenThrowException() {
        TIFJobParameter tifJobParameter = randomTifJobParameter();
        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            DeleteResponse response = mock(DeleteResponse.class);
            when(response.status()).thenReturn(RestStatus.NOT_FOUND);
            return response;
        });

        // Run
        expectThrows(ResourceNotFoundException.class, () -> tifJobParameterService.deleteTIFJobParameter(tifJobParameter));
    }

    public void testGetTifJobParameter_whenValidInput_thenSucceed() {
        List<TIFJobParameter> tifJobParameters = Arrays.asList(randomTifJobParameter(), randomTifJobParameter());
        String[] names = tifJobParameters.stream().map(TIFJobParameter::getName).toArray(String[]::new);
        ActionListener<List<TIFJobParameter>> listener = mock(ActionListener.class);
        MultiGetItemResponse[] multiGetItemResponses = tifJobParameters.stream().map(tifJobParameter -> {
            GetResponse getResponse = getMockedGetResponse(tifJobParameter);
            MultiGetItemResponse multiGetItemResponse = mock(MultiGetItemResponse.class);
            when(multiGetItemResponse.getResponse()).thenReturn(getResponse);
            return multiGetItemResponse;
        }).toArray(MultiGetItemResponse[]::new);

        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            // Verify
            assertTrue(actionRequest instanceof MultiGetRequest);
            MultiGetRequest request = (MultiGetRequest) actionRequest;
            assertEquals(2, request.getItems().size());
            for (MultiGetRequest.Item item : request.getItems()) {
                assertEquals(TIFJobExtension.JOB_INDEX_NAME, item.index());
                assertTrue(tifJobParameters.stream().filter(tifJobParameter -> tifJobParameter.getName().equals(item.id())).findAny().isPresent());
            }

            MultiGetResponse response = mock(MultiGetResponse.class);
            when(response.getResponses()).thenReturn(multiGetItemResponses);
            return response;
        });

        // Run
        tifJobParameterService.getTIFJobParameters(names, listener);

        // Verify
        ArgumentCaptor<List<TIFJobParameter>> captor = ArgumentCaptor.forClass(List.class);
        verify(listener).onResponse(captor.capture());
        assertEquals(tifJobParameters, captor.getValue());

    }

    public void testGetAllTifJobParameter_whenAsynchronous_thenSuccee() {
        List<TIFJobParameter> tifJobParameters = Arrays.asList(randomTifJobParameter(), randomTifJobParameter());
        ActionListener<List<TIFJobParameter>> listener = mock(ActionListener.class);
        SearchHits searchHits = getMockedSearchHits(tifJobParameters);

        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            // Verify
            assertTrue(actionRequest instanceof SearchRequest);
            SearchRequest request = (SearchRequest) actionRequest;
            assertEquals(1, request.indices().length);
            assertEquals(TIFJobExtension.JOB_INDEX_NAME, request.indices()[0]);
            assertEquals(QueryBuilders.matchAllQuery(), request.source().query());
            assertEquals(1000, request.source().size());
            assertEquals(Preference.PRIMARY.type(), request.preference());

            SearchResponse response = mock(SearchResponse.class);
            when(response.getHits()).thenReturn(searchHits);
            return response;
        });

        // Run
        tifJobParameterService.getAllTIFJobParameters(listener);

        // Verify
        ArgumentCaptor<List<TIFJobParameter>> captor = ArgumentCaptor.forClass(List.class);
        verify(listener).onResponse(captor.capture());
        assertEquals(tifJobParameters, captor.getValue());
    }

    public void testGetAllTifJobParameter_whenSynchronous_thenSucceed() {
        List<TIFJobParameter> tifJobParameters = Arrays.asList(randomTifJobParameter(), randomTifJobParameter());
        SearchHits searchHits = getMockedSearchHits(tifJobParameters);

        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            // Verify
            assertTrue(actionRequest instanceof SearchRequest);
            SearchRequest request = (SearchRequest) actionRequest;
            assertEquals(1, request.indices().length);
            assertEquals(TIFJobExtension.JOB_INDEX_NAME, request.indices()[0]);
            assertEquals(QueryBuilders.matchAllQuery(), request.source().query());
            assertEquals(1000, request.source().size());
            assertEquals(Preference.PRIMARY.type(), request.preference());

            SearchResponse response = mock(SearchResponse.class);
            when(response.getHits()).thenReturn(searchHits);
            return response;
        });

        // Run
        tifJobParameterService.getAllTIFJobParameters();

        // Verify
        assertEquals(tifJobParameters, tifJobParameterService.getAllTIFJobParameters());
    }

    public void testUpdateTifJobParameter_whenValidInput_thenUpdate() {
        List<TIFJobParameter> tifJobParameters = Arrays.asList(randomTifJobParameter(), randomTifJobParameter());

        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            // Verify
            assertTrue(actionRequest instanceof BulkRequest);
            BulkRequest bulkRequest = (BulkRequest) actionRequest;
            assertEquals(2, bulkRequest.requests().size());
            for (int i = 0; i < bulkRequest.requests().size(); i++) {
                IndexRequest request = (IndexRequest) bulkRequest.requests().get(i);
                assertEquals(TIFJobExtension.JOB_INDEX_NAME, request.index());
                assertEquals(tifJobParameters.get(i).getName(), request.id());
                assertEquals(DocWriteRequest.OpType.INDEX, request.opType());
            }
            return null;
        });

        tifJobParameterService.updateJobSchedulerParameter(tifJobParameters, mock(ActionListener.class));
    }

    private SearchHits getMockedSearchHits(List<TIFJobParameter> tifJobParameters) {
        SearchHit[] searchHitArray = tifJobParameters.stream().map(this::toBytesReference).map(this::toSearchHit).toArray(SearchHit[]::new);

        return new SearchHits(searchHitArray, new TotalHits(1l, TotalHits.Relation.EQUAL_TO), 1);
    }

    private GetResponse getMockedGetResponse(TIFJobParameter tifJobParameter) {
        GetResponse response = mock(GetResponse.class);
        when(response.isExists()).thenReturn(tifJobParameter != null);
        when(response.getSourceAsBytesRef()).thenReturn(toBytesReference(tifJobParameter));
        return response;
    }

    private BytesReference toBytesReference(TIFJobParameter tifJobParameter) {
        if (tifJobParameter == null) {
            return null;
        }

        try {
            return BytesReference.bytes(tifJobParameter.toXContent(JsonXContent.contentBuilder(), null));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private SearchHit toSearchHit(BytesReference bytesReference) {
        SearchHit searchHit = new SearchHit(Randomness.get().nextInt());
        searchHit.sourceRef(bytesReference);
        return searchHit;
    }
}
