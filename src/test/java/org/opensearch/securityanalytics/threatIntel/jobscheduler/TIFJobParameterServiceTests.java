/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.junit.Before;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.TestHelpers;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/*public class TIFJobParameterServiceTests extends ThreatIntelTestCase {
    private TIFJobParameterService tifJobParameterService;

    @Before
    public void init() {
        tifJobParameterService = new TIFJobParameterService(verifyingClient, clusterService);
    }

    public void testcreateJobIndexIfNotExists_whenIndexExist_thenCreateRequestIsNotCalled() {
        when(metadata.hasIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME)).thenReturn(true);

        // Verify
        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> { throw new RuntimeException("Shouldn't get called"); });

        // Run
        StepListener<Void> stepListener = new StepListener<>();
        tifJobParameterService.createJobIndexIfNotExists(stepListener);

        // Verify stepListener is called
        stepListener.result();
    }

    public void testcreateJobIndexIfNotExists_whenIndexExist_thenCreateRequestIsCalled() {
        when(metadata.hasIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME)).thenReturn(false);

        // Verify
        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            assertTrue(actionRequest instanceof CreateIndexRequest);
            CreateIndexRequest request = (CreateIndexRequest) actionRequest;
            assertEquals(SecurityAnalyticsPlugin.JOB_INDEX_NAME, request.index());
            assertEquals("1", request.settings().get("index.number_of_shards"));
            assertEquals("0-all", request.settings().get("index.auto_expand_replicas"));
            assertEquals("true", request.settings().get("index.hidden"));
            assertNotNull(request.mappings());
            return null;
        });

        // Run
        StepListener<Void> stepListener = new StepListener<>();
        tifJobParameterService.createJobIndexIfNotExists(stepListener);

        // Verify stepListener is called
        stepListener.result();
    }

    public void testcreateJobIndexIfNotExists_whenIndexCreatedAlready_thenExceptionIsIgnored() {
        when(metadata.hasIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME)).thenReturn(false);
        verifyingClient.setExecuteVerifier(
                (actionResponse, actionRequest) -> { throw new ResourceAlreadyExistsException(SecurityAnalyticsPlugin.JOB_INDEX_NAME); }
        );

        // Run
        StepListener<Void> stepListener = new StepListener<>();
        tifJobParameterService.createJobIndexIfNotExists(stepListener);

        // Verify stepListener is called
        stepListener.result();
    }

    public void testcreateJobIndexIfNotExists_whenExceptionIsThrown_thenExceptionIsThrown() {
        when(metadata.hasIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME)).thenReturn(false);
        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> { throw new RuntimeException(); });

        // Run
        StepListener<Void> stepListener = new StepListener<>();
        tifJobParameterService.createJobIndexIfNotExists(stepListener);

        // Verify stepListener is called
        expectThrows(RuntimeException.class, () -> stepListener.result());
    }

    public void testUpdateTIFJobParameter_whenValidInput_thenSucceed() throws Exception {
        String tifJobName = TestHelpers.randomLowerCaseString();
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
            assertEquals(SecurityAnalyticsPlugin.JOB_INDEX_NAME, request.index());
            assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, request.getRefreshPolicy());
            return null;
        });

        tifJobParameterService.updateJobSchedulerParameter(tifJobParameter);
        assertTrue(previousTime.isBefore(tifJobParameter.getLastUpdateTime()));
    }

    public void testsaveTIFJobParameter_whenValidInput_thenSucceed() {
        TIFJobParameter tifJobParameter = randomTifJobParameter();
        Instant previousTime = Instant.now().minusMillis(1);
        tifJobParameter.setLastUpdateTime(previousTime);

        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            assertTrue(actionRequest instanceof IndexRequest);
            IndexRequest indexRequest = (IndexRequest) actionRequest;
            assertEquals(SecurityAnalyticsPlugin.JOB_INDEX_NAME, indexRequest.index());
            assertEquals(tifJobParameter.getName(), indexRequest.id());
            assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, indexRequest.getRefreshPolicy());
            assertEquals(DocWriteRequest.OpType.CREATE, indexRequest.opType());
            return null;
        });

        tifJobParameterService.saveTIFJobParameter(tifJobParameter, mock(ActionListener.class));
        assertTrue(previousTime.isBefore(tifJobParameter.getLastUpdateTime()));
    }

    public void testGetTifJobParameter_whenException_thenNull() throws Exception {
        TIFJobParameter tifJobParameter = setupClientForGetRequest(true, new IndexNotFoundException(SecurityAnalyticsPlugin.JOB_INDEX_NAME));
        assertNull(tifJobParameterService.getJobParameter(tifJobParameter.getName()));
    }

    public void testGetTifJobParameter_whenExist_thenReturnTifJobParameter() throws Exception {
        TIFJobParameter tifJobParameter = setupClientForGetRequest(true, null);
        TIFJobParameter anotherTIFJobParameter = tifJobParameterService.getJobParameter(tifJobParameter.getName());

        assertTrue(tifJobParameter.getName().equals(anotherTIFJobParameter.getName()));
        assertTrue(tifJobParameter.getLastUpdateTime().equals(anotherTIFJobParameter.getLastUpdateTime()));
        assertTrue(tifJobParameter.getSchedule().equals(anotherTIFJobParameter.getSchedule()));
        assertTrue(tifJobParameter.getState().equals(anotherTIFJobParameter.getState()));
        assertTrue(tifJobParameter.getIndices().equals(anotherTIFJobParameter.getIndices()));
    }

    public void testGetTifJobParameter_whenNotExist_thenNull() throws Exception {
        TIFJobParameter tifJobParameter = setupClientForGetRequest(false, null);
        assertNull(tifJobParameterService.getJobParameter(tifJobParameter.getName()));
    }

    private TIFJobParameter setupClientForGetRequest(final boolean isExist, final RuntimeException exception) {
        TIFJobParameter tifJobParameter = randomTifJobParameter();

        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            assertTrue(actionRequest instanceof GetRequest);
            GetRequest request = (GetRequest) actionRequest;
            assertEquals(tifJobParameter.getName(), request.id());
            assertEquals(SecurityAnalyticsPlugin.JOB_INDEX_NAME, request.index());
            GetResponse response = getMockedGetResponse(isExist ? tifJobParameter : null);
            if (exception != null) {
                throw exception;
            }
            return response;
        });
        return tifJobParameter;
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

}*/
