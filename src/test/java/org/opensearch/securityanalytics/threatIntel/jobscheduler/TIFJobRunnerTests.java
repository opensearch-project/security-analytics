
/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

import org.junit.Before;

import org.opensearch.jobscheduler.spi.JobDocVersion;
import org.opensearch.jobscheduler.spi.JobExecutionContext;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.jobscheduler.spi.ScheduledJobParameter;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestHelper;
import org.opensearch.securityanalytics.threatIntel.common.TIFState;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;

public class TIFJobRunnerTests extends ThreatIntelTestCase {
    @Before
    public void init() {
        TIFJobRunner.getJobRunnerInstance()
                .initialize(clusterService, datasourceUpdateService, datasourceDao, threatIntelExecutor, threatIntelLockService);
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
        TIFJobParameter datasource = randomDatasource();

        LockModel lockModel = randomLockModel();
        when(threatIntelLockService.acquireLock(datasource.getName(), TIFLockService.LOCK_DURATION_IN_SECONDS)).thenReturn(
                Optional.of(lockModel)
        );

        // Run
        TIFJobRunner.getJobRunnerInstance().runJob(datasource, jobExecutionContext);

        // Verify
        verify(threatIntelLockService).acquireLock(datasource.getName(), threatIntelLockService.LOCK_DURATION_IN_SECONDS);
        verify(datasourceDao).getJobParameter(datasource.getName());
        verify(threatIntelLockService).releaseLock(lockModel);
    }

    public void testUpdateDatasourceRunner_whenExceptionBeforeAcquiringLock_thenNoReleaseLock() {
        ScheduledJobParameter jobParameter = mock(ScheduledJobParameter.class);
        when(jobParameter.getName()).thenReturn(ThreatIntelTestHelper.randomLowerCaseString());
        when(threatIntelLockService.acquireLock(jobParameter.getName(), TIFLockService.LOCK_DURATION_IN_SECONDS)).thenThrow(
                new RuntimeException()
        );

        // Run
        expectThrows(Exception.class, () -> TIFJobRunner.getJobRunnerInstance().updateJobRunner(jobParameter).run());

        // Verify
        verify(threatIntelLockService, never()).releaseLock(any());
    }

    public void testUpdateDatasourceRunner_whenExceptionAfterAcquiringLock_thenReleaseLock() throws IOException {
        ScheduledJobParameter jobParameter = mock(ScheduledJobParameter.class);
        when(jobParameter.getName()).thenReturn(ThreatIntelTestHelper.randomLowerCaseString());
        LockModel lockModel = randomLockModel();
        when(threatIntelLockService.acquireLock(jobParameter.getName(), TIFLockService.LOCK_DURATION_IN_SECONDS)).thenReturn(
                Optional.of(lockModel)
        );
        when(datasourceDao.getJobParameter(jobParameter.getName())).thenThrow(new RuntimeException());

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobRunner(jobParameter).run();

        // Verify
        verify(threatIntelLockService).releaseLock(any());
    }

    public void testUpdateDatasource_whenDatasourceDoesNotExist_thenDoNothing() throws IOException {
        TIFJobParameter datasource = new TIFJobParameter();

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobParameter(datasource, mock(Runnable.class));

        // Verify
        verify(datasourceUpdateService, never()).deleteUnusedIndices(any());
    }

    public void testUpdateDatasource_whenInvalidState_thenUpdateLastFailedAt() throws IOException {
        TIFJobParameter datasource = new TIFJobParameter();
        datasource.enable();
        datasource.getUpdateStats().setLastFailedAt(null);
        datasource.setState(randomStateExcept(TIFState.AVAILABLE));
        when(datasourceDao.getJobParameter(datasource.getName())).thenReturn(datasource);

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobParameter(datasource, mock(Runnable.class));

        // Verify
        assertFalse(datasource.isEnabled());
        assertNotNull(datasource.getUpdateStats().getLastFailedAt());
        verify(datasourceDao).updateJobSchedulerParameter(datasource);
    }

    public void testUpdateDatasource_whenValidInput_thenSucceed() throws IOException {
        TIFJobParameter datasource = randomDatasource();
        datasource.setState(TIFState.AVAILABLE);
        when(datasourceDao.getJobParameter(datasource.getName())).thenReturn(datasource);
        Runnable renewLock = mock(Runnable.class);

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobParameter(datasource, renewLock);

        // Verify
        verify(datasourceUpdateService, times(2)).deleteUnusedIndices(datasource);
        verify(datasourceUpdateService).createThreatIntelFeedData(datasource, renewLock);
        verify(datasourceUpdateService).updateJobSchedulerParameter(datasource, datasource.getSchedule(), TIFJobTask.ALL);
    }

    public void testUpdateDatasource_whenDeleteTask_thenDeleteOnly() throws IOException {
        TIFJobParameter datasource = randomDatasource();
        datasource.setState(TIFState.AVAILABLE);
        datasource.setTask(TIFJobTask.DELETE_UNUSED_INDICES);
        when(datasourceDao.getJobParameter(datasource.getName())).thenReturn(datasource);
        Runnable renewLock = mock(Runnable.class);

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobParameter(datasource, renewLock);

        // Verify
        verify(datasourceUpdateService, times(2)).deleteUnusedIndices(datasource);
        verify(datasourceUpdateService, never()).createThreatIntelFeedData(datasource, renewLock);
        verify(datasourceUpdateService).updateJobSchedulerParameter(datasource, datasource.getSchedule(), TIFJobTask.ALL);
    }

    public void testUpdateDatasourceExceptionHandling() throws IOException {
        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setName(ThreatIntelTestHelper.randomLowerCaseString());
        datasource.getUpdateStats().setLastFailedAt(null);
        when(datasourceDao.getJobParameter(datasource.getName())).thenReturn(datasource);
        doThrow(new RuntimeException("test failure")).when(datasourceUpdateService).deleteUnusedIndices(any());

        // Run
        TIFJobRunner.getJobRunnerInstance().updateJobParameter(datasource, mock(Runnable.class));

        // Verify
        assertNotNull(datasource.getUpdateStats().getLastFailedAt());
        verify(datasourceDao).updateJobSchedulerParameter(datasource);
    }
}

