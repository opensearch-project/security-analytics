
/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.junit.Before;
import org.opensearch.jobscheduler.spi.JobDocVersion;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestHelper;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class TIFJobRunnerTests extends ThreatIntelTestCase {
    @Before
    public void init() {
        TIFJobRunner.getJobRunnerInstance()
                .initialize(clusterService, tifJobUpdateService, tifJobParameterService, tifLockService, threadPool);
    }

    public void testGetJobRunnerInstance_whenCalledAgain_thenReturnSameInstance() {
        assertTrue(TIFJobRunner.getJobRunnerInstance() == TIFJobRunner.getJobRunnerInstance());
    }

    public void testRunJob_whenInvalidClass_thenThrowException() {
        JobDocVersion jobDocVersion = new JobDocVersion(randomInt(), randomInt(), randomInt());
        String jobIndexName = ThreatIntelTestHelper.randomLowerCaseString();
        String jobId = ThreatIntelTestHelper.randomLowerCaseString();
        JobExecutionContext jobExecutionContext = new JobExecutionContext(Instant.now(), jobDocVersion, lockService, jobIndexName, jobId);
        ScheduledJobParameter jobParameter = mock(ScheduledJobParameter.class);

        // Run
        expectThrows(IllegalStateException.class, () -> TIFJobRunner.getJobRunnerInstance().runJob(jobParameter, jobExecutionContext));
    }

    public void testRunJob_whenValidInput_thenSucceed() throws IOException {
        JobDocVersion jobDocVersion = new JobDocVersion(randomInt(), randomInt(), randomInt());
        String jobIndexName = ThreatIntelTestHelper.randomLowerCaseString();
        String jobId = ThreatIntelTestHelper.randomLowerCaseString();
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
        when(jobParameter.getName()).thenReturn(ThreatIntelTestHelper.randomLowerCaseString());
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
        when(jobParameter.getName()).thenReturn(ThreatIntelTestHelper.randomLowerCaseString());
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
        verify(tifJobUpdateService, never()).deleteAllTifdIndices(ThreatIntelTestHelper.randomLowerCaseStringList(),ThreatIntelTestHelper.randomLowerCaseStringList());
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
        verify(tifJobUpdateService, times(0)).deleteAllTifdIndices(ThreatIntelTestHelper.randomLowerCaseStringList(),ThreatIntelTestHelper.randomLowerCaseStringList());
        verify(tifJobUpdateService).createThreatIntelFeedData(tifJob, renewLock);
//        verify(tifJobUpdateService).updateJobSchedulerParameter(tifJob, tifJob.getSchedule(), TIFJobTask.ALL);
    }

//    public void testUpdateTIFJob_whenDeleteTask_thenDeleteOnly() throws IOException {
//        TIFJobParameter tifJob = randomTifJobParameter();
//        tifJob.setState(TIFJobState.AVAILABLE);
//        when(tifJobParameterService.getJobParameter(tifJob.getName())).thenReturn(tifJob);
//        Runnable renewLock = mock(Runnable.class);
//
//        // Run
//        TIFJobRunner.getJobRunnerInstance().updateJobParameter(tifJob, renewLock);
//
//        // Verify
//        verify(tifJobUpdateService, times(0)).deleteAllTifdIndices(ThreatIntelTestHelper.randomLowerCaseStringList(),ThreatIntelTestHelper.randomLowerCaseStringList());
////        verify(tifJobUpdateService).updateJobSchedulerParameter(tifJob, tifJob.getSchedule(), TIFJobTask.ALL);
//    }

    public void testUpdateTIFJobExceptionHandling() throws IOException {
        TIFJobParameter tifJob = new TIFJobParameter();
        tifJob.setName(ThreatIntelTestHelper.randomLowerCaseString());
        tifJob.getUpdateStats().setLastFailedAt(null);
        when(tifJobParameterService.getJobParameter(tifJob.getName())).thenReturn(tifJob);
        doThrow(new RuntimeException("test failure")).when(tifJobUpdateService).deleteAllTifdIndices(ThreatIntelTestHelper.randomLowerCaseStringList(),ThreatIntelTestHelper.randomLowerCaseStringList());

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobParameter(tifJob, mock(Runnable.class));

        // Verify
        assertNotNull(tifJob.getUpdateStats().getLastFailedAt());
        verify(tifJobParameterService).updateJobSchedulerParameter(tifJob);
    }
}

