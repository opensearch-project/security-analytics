/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.junit.Before;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.opensearch.OpenSearchException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameter;
import org.opensearch.tasks.Task;
import org.opensearch.securityanalytics.TestHelpers;


import java.io.IOException;
import java.time.Instant;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class TransportDeleteTIFJobActionTests extends ThreatIntelTestCase {
    private TransportDeleteTIFJobAction action;

    @Before
    public void init() {
        action = new TransportDeleteTIFJobAction(
            transportService,
            actionFilters,
            tifLockService,
            ingestService,
            tifJobParameterService,
            threatIntelFeedDataService,
            threadPool
        );
    }

    public void testDoExecute_whenFailedToAcquireLock_thenError() throws IOException {
        validateDoExecute(null, null);
    }

    public void testDoExecute_whenValidInput_thenSucceed() throws IOException {
        String jobIndexName = TestHelpers.randomLowerCaseString();
        String jobId = TestHelpers.randomLowerCaseString();
        LockModel lockModel = new LockModel(jobIndexName, jobId, Instant.now(), randomPositiveLong(), false);
        validateDoExecute(lockModel, null);
    }

    public void testDoExecute_whenException_thenError() throws IOException {
        validateDoExecute(null, new RuntimeException());
    }

    private void validateDoExecute(final LockModel lockModel, final Exception exception) throws IOException {
        Task task = mock(Task.class);
        TIFJobParameter tifJobParameter = randomTifJobParameter();
        when(tifJobParameterService.getJobParameter(tifJobParameter.getName())).thenReturn(tifJobParameter);
        DeleteTIFJobRequest request = new DeleteTIFJobRequest(tifJobParameter.getName());
        ActionListener<AcknowledgedResponse> listener = mock(ActionListener.class);

        // Run
        action.doExecute(task, request, listener);

        // Verify
        ArgumentCaptor<ActionListener<LockModel>> captor = ArgumentCaptor.forClass(ActionListener.class);
        verify(tifLockService).acquireLock(eq(tifJobParameter.getName()), anyLong(), captor.capture());

        if (exception == null) {
            // Run
            captor.getValue().onResponse(lockModel);

            // Verify
            if (lockModel == null) {
                verify(listener).onFailure(any(OpenSearchException.class));
            } else {
                verify(listener).onResponse(new AcknowledgedResponse(true));
                verify(tifLockService).releaseLock(eq(lockModel));
            }
        } else {
            // Run
            captor.getValue().onFailure(exception);
            // Verify
            verify(listener).onFailure(exception);
        }
    }

    public void testDeleteTIFJobParameter_whenNull_thenThrowException() {
        TIFJobParameter tifJobParameter = randomTifJobParameter();
        expectThrows(ResourceNotFoundException.class, () -> action.deleteTIFJob(tifJobParameter.getName()));
    }

    public void testDeleteTIFJobParameter_whenSafeToDelete_thenDelete() throws IOException {
        TIFJobParameter tifJobParameter = randomTifJobParameter();
        when(tifJobParameterService.getJobParameter(tifJobParameter.getName())).thenReturn(tifJobParameter);

        // Run
        action.deleteTIFJob(tifJobParameter.getName());

        // Verify
        assertEquals(TIFJobState.DELETING, tifJobParameter.getState());
        verify(tifJobParameterService).updateJobSchedulerParameter(tifJobParameter);
        InOrder inOrder = Mockito.inOrder(threatIntelFeedDataService, tifJobParameterService);
        inOrder.verify(threatIntelFeedDataService).deleteThreatIntelDataIndex(tifJobParameter.getIndices());
        inOrder.verify(tifJobParameterService).deleteTIFJobParameter(tifJobParameter);
    }

    public void testDeleteTIFJobParameter_whenDeleteFailsAfterStateIsChanged_thenRevertState() throws IOException {
        TIFJobParameter tifJobParameter = randomTifJobParameter();
        tifJobParameter.setState(TIFJobState.AVAILABLE);
        when(tifJobParameterService.getJobParameter(tifJobParameter.getName())).thenReturn(tifJobParameter);
        doThrow(new RuntimeException()).when(threatIntelFeedDataService).deleteThreatIntelDataIndex(tifJobParameter.getIndices());

        // Run
        expectThrows(RuntimeException.class, () -> action.deleteTIFJob(tifJobParameter.getName()));

        // Verify
        verify(tifJobParameterService, times(2)).updateJobSchedulerParameter(tifJobParameter);
        assertEquals(TIFJobState.AVAILABLE, tifJobParameter.getState());
    }
}
