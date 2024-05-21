
/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import static org.mockito.ArgumentMatchers.any;

/*public class TIFJobRunnerTests extends ThreatIntelTestCase {
    @Before
    public void init() {
        TIFJobRunner.getJobRunnerInstance()
                .initialize(clusterService, tifJobUpdateService, tifJobParameterService, tifLockService, threadPool, detectorThreatIntelService);
    }

    public void testGetJobRunnerInstance_whenCalledAgain_thenReturnSameInstance() {
        assertTrue(TIFJobRunner.getJobRunnerInstance() == TIFJobRunner.getJobRunnerInstance());
    }

    public void testRunJob_whenInvalidClass_thenThrowException() {
        JobDocVersion jobDocVersion = new JobDocVersion(randomInt(), randomInt(), randomInt());
        String jobIndexName = TestHelpers.randomLowerCaseString();
        String jobId = TestHelpers.randomLowerCaseString();
        JobExecutionContext jobExecutionContext = new JobExecutionContext(Instant.now(), jobDocVersion, lockService, jobIndexName, jobId);
        ScheduledJobParameter jobParameter = mock(ScheduledJobParameter.class);

        // Run
        expectThrows(IllegalStateException.class, () -> TIFJobRunner.getJobRunnerInstance().runJob(jobParameter, jobExecutionContext));
    }

    public void testRunJob_whenValidInput_thenSucceed() throws IOException {
        JobDocVersion jobDocVersion = new JobDocVersion(randomInt(), randomInt(), randomInt());
        String jobIndexName = TestHelpers.randomLowerCaseString();
        String jobId = TestHelpers.randomLowerCaseString();
        JobExecutionContext jobExecutionContext = new JobExecutionContext(Instant.now(), jobDocVersion, lockService, jobIndexName, jobId);
        TIFJobParameter tifJobParameter = randomTifJobParameter();

        LockModel lockModel = randomLockModel();
        when(tifLockService.acquireLock(tifJobParameter.getName(), TIFLockService.LOCK_DURATION_IN_SECONDS)).thenReturn(
                Optional.of(lockModel)
        );

        // Run
        TIFJobRunner.getJobRunnerInstance().runJob(tifJobParameter, jobExecutionContext);

        // Verify
        verify(tifLockService).acquireLock(tifJobParameter.getName(), tifLockService.LOCK_DURATION_IN_SECONDS);
        verify(tifJobParameterService).getJobParameter(tifJobParameter.getName());
        verify(tifLockService).releaseLock(lockModel);
    }

    public void testUpdateTIFJobRunner_whenExceptionBeforeAcquiringLock_thenNoReleaseLock() {
        ScheduledJobParameter jobParameter = mock(ScheduledJobParameter.class);
        when(jobParameter.getName()).thenReturn(TestHelpers.randomLowerCaseString());
        when(tifLockService.acquireLock(jobParameter.getName(), TIFLockService.LOCK_DURATION_IN_SECONDS)).thenThrow(
                new RuntimeException()
        );

        // Run
        expectThrows(Exception.class, () -> TIFJobRunner.getJobRunnerInstance().updateJobRunner(jobParameter).run());

        // Verify
        verify(tifLockService, never()).releaseLock(any());
    }

    public void testUpdateTIFJobRunner_whenExceptionAfterAcquiringLock_thenReleaseLock() throws IOException {
        ScheduledJobParameter jobParameter = mock(ScheduledJobParameter.class);
        when(jobParameter.getName()).thenReturn(TestHelpers.randomLowerCaseString());
        LockModel lockModel = randomLockModel();
        when(tifLockService.acquireLock(jobParameter.getName(), TIFLockService.LOCK_DURATION_IN_SECONDS)).thenReturn(
                Optional.of(lockModel)
        );
        when(tifJobParameterService.getJobParameter(jobParameter.getName())).thenThrow(new RuntimeException());

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobRunner(jobParameter).run();

        // Verify
        verify(tifLockService).releaseLock(any());
    }

    public void testUpdateTIFJob_whenTIFJobDoesNotExist_thenDoNothing() throws IOException {
        TIFJobParameter tifJob = new TIFJobParameter();

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobParameter(tifJob, mock(Runnable.class));

        // Verify
        verify(tifJobUpdateService, never()).deleteAllTifdIndices(TestHelpers.randomLowerCaseStringList(),TestHelpers.randomLowerCaseStringList());
    }

    public void testUpdateTIFJob_whenInvalidState_thenUpdateLastFailedAt() throws IOException {
        TIFJobParameter tifJob = new TIFJobParameter();
        tifJob.enable();
        tifJob.getUpdateStats().setLastFailedAt(null);
        tifJob.setState(randomStateExcept(TIFJobState.AVAILABLE));
        when(tifJobParameterService.getJobParameter(tifJob.getName())).thenReturn(tifJob);

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobParameter(tifJob, mock(Runnable.class));

        // Verify
        assertFalse(tifJob.isEnabled());
        assertNotNull(tifJob.getUpdateStats().getLastFailedAt());
        verify(tifJobParameterService).updateJobSchedulerParameter(tifJob);
    }

    public void testUpdateTIFJob_whenValidInput_thenSucceed() throws IOException {
        TIFJobParameter tifJob = randomTifJobParameter();
        tifJob.setState(TIFJobState.AVAILABLE);
        when(tifJobParameterService.getJobParameter(tifJob.getName())).thenReturn(tifJob);
        Runnable renewLock = mock(Runnable.class);

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobParameter(tifJob, renewLock);

        // Verify
        verify(tifJobUpdateService, times(0)).deleteAllTifdIndices(TestHelpers.randomLowerCaseStringList(),TestHelpers.randomLowerCaseStringList());
        verify(tifJobUpdateService).createThreatIntelFeedData(tifJob, renewLock);
    }

    public void testUpdateTIFJob_whenDeleteTask_thenDeleteOnly() throws IOException {
        TIFJobParameter tifJob = randomTifJobParameter();
        tifJob.setState(TIFJobState.AVAILABLE);
        when(tifJobParameterService.getJobParameter(tifJob.getName())).thenReturn(tifJob);
        Runnable renewLock = mock(Runnable.class);

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobParameter(tifJob, renewLock);

        // Verify
        verify(tifJobUpdateService, times(0)).deleteAllTifdIndices(TestHelpers.randomLowerCaseStringList(),TestHelpers.randomLowerCaseStringList());
    }

    public void testUpdateTIFJobExceptionHandling() throws IOException {
        TIFJobParameter tifJob = new TIFJobParameter();
        tifJob.setName(TestHelpers.randomLowerCaseString());
        tifJob.getUpdateStats().setLastFailedAt(null);
        when(tifJobParameterService.getJobParameter(tifJob.getName())).thenReturn(tifJob);
        doThrow(new RuntimeException("test failure")).when(tifJobUpdateService).deleteAllTifdIndices(TestHelpers.randomLowerCaseStringList(),TestHelpers.randomLowerCaseStringList());

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobParameter(tifJob, mock(Runnable.class));

        // Verify
        assertNotNull(tifJob.getUpdateStats().getLastFailedAt());
        verify(tifJobParameterService).updateJobSchedulerParameter(tifJob);
    }
}*/

