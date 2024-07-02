/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

/*public class TransportPutTIFJobActionTests extends ThreatIntelTestCase {
    private TransportPutTIFJobAction action;

    @Before
    public void init() {
        action = new TransportPutTIFJobAction(
            transportService,
            actionFilters,
            threadPool,
            tifJobParameterService,
            tifJobUpdateService,
            tifLockService
        );
    }

    public void testDoExecute_whenFailedToAcquireLock_thenError() throws IOException {
        validateDoExecute(null, null, null);
    }

    public void testDoExecute_whenAcquiredLock_thenSucceed() throws IOException {
        validateDoExecute(randomLockModel(), null, null);
    }

    public void testDoExecute_whenExceptionBeforeAcquiringLock_thenError() throws IOException {
        validateDoExecute(randomLockModel(), new RuntimeException(), null);
    }

    public void testDoExecute_whenExceptionAfterAcquiringLock_thenError() throws IOException {
        validateDoExecute(randomLockModel(), null, new RuntimeException());
    }

    private void validateDoExecute(final LockModel lockModel, final Exception before, final Exception after) throws IOException {
        Task task = mock(Task.class);
        TIFJobParameter tifJobParameter = randomTifJobParameter();

        PutTIFJobRequest request = new PutTIFJobRequest(tifJobParameter.getName(), clusterSettings.get(SecurityAnalyticsSettings.TIF_UPDATE_INTERVAL));
        ActionListener<AcknowledgedResponse> listener = mock(ActionListener.class);
        if (after != null) {
            doThrow(after).when(tifJobParameterService).createJobIndexIfNotExists(any(StepListener.class));
        }

        // Run
        action.doExecute(task, request, listener);

        // Verify
        ArgumentCaptor<ActionListener<LockModel>> captor = ArgumentCaptor.forClass(ActionListener.class);
        verify(tifLockService).acquireLock(eq(tifJobParameter.getName()), anyLong(), captor.capture());

        if (before == null) {
            // Run
            captor.getValue().onResponse(lockModel);

            // Verify
            if (lockModel == null) {
                verify(listener).onFailure(any(ConcurrentModificationException.class));
            }
            if (after != null) {
                verify(tifLockService).releaseLock(eq(lockModel));
                verify(listener).onFailure(after);
            } else {
                verify(tifLockService, never()).releaseLock(eq(lockModel));
            }
        } else {
            // Run
            captor.getValue().onFailure(before);
            // Verify
            verify(listener).onFailure(before);
        }
    }

    public void testInternalDoExecute_whenValidInput_thenSucceed() {
        PutTIFJobRequest request = new PutTIFJobRequest(TestHelpers.randomLowerCaseString(), clusterSettings.get(SecurityAnalyticsSettings.TIF_UPDATE_INTERVAL));
        ActionListener<AcknowledgedResponse> listener = mock(ActionListener.class);

        // Run
        action.internalDoExecute(request, randomLockModel(), listener);

        // Verify
        ArgumentCaptor<StepListener> captor = ArgumentCaptor.forClass(StepListener.class);
        verify(tifJobParameterService).createJobIndexIfNotExists(captor.capture());

        // Run
        captor.getValue().onResponse(null);
        // Verify
        ArgumentCaptor<TIFJobParameter> tifJobCaptor = ArgumentCaptor.forClass(TIFJobParameter.class);
        ArgumentCaptor<ActionListener> actionListenerCaptor = ArgumentCaptor.forClass(ActionListener.class);
        verify(tifJobParameterService).saveTIFJobParameter(tifJobCaptor.capture(), actionListenerCaptor.capture());
        assertEquals(request.getName(), tifJobCaptor.getValue().getName());

        // Run next listener.onResponse
        actionListenerCaptor.getValue().onResponse(null);
        // Verify
        verify(listener).onResponse(new AcknowledgedResponse(true));
    }

    public void testCreateTIFJobParameter_whenInvalidState_thenUpdateStateAsFailed() throws IOException {
        TIFJobParameter tifJob = new TIFJobParameter();
        tifJob.setState(randomStateExcept(TIFJobState.CREATING));
        tifJob.getUpdateStats().setLastFailedAt(null);

        // Run
        action.createThreatIntelFeedData(tifJob, mock(Runnable.class));

        // Verify
        assertEquals(TIFJobState.CREATE_FAILED, tifJob.getState());
        assertNotNull(tifJob.getUpdateStats().getLastFailedAt());
        verify(tifJobParameterService).updateJobSchedulerParameter(tifJob);
        verify(tifJobUpdateService, never()).createThreatIntelFeedData(any(TIFJobParameter.class), any(Runnable.class));
    }

    public void testCreateTIFJobParameter_whenExceptionHappens_thenUpdateStateAsFailed() throws IOException {
        TIFJobParameter tifJob = new TIFJobParameter();
        doThrow(new RuntimeException()).when(tifJobUpdateService).createThreatIntelFeedData(any(TIFJobParameter.class), any(Runnable.class));

        // Run
        action.createThreatIntelFeedData(tifJob, mock(Runnable.class));

        // Verify
        assertEquals(TIFJobState.CREATE_FAILED, tifJob.getState());
        assertNotNull(tifJob.getUpdateStats().getLastFailedAt());
        verify(tifJobParameterService).updateJobSchedulerParameter(tifJob);
    }

    public void testCreateTIFJobParameter_whenValidInput_thenUpdateStateAsCreating() throws IOException {
        TIFJobParameter tifJob = new TIFJobParameter();

        Runnable renewLock = mock(Runnable.class);
        // Run
        action.createThreatIntelFeedData(tifJob, renewLock);

        // Verify
        verify(tifJobUpdateService).createThreatIntelFeedData(tifJob, renewLock);
        assertEquals(TIFJobState.CREATING, tifJob.getState());
    }
}*/
