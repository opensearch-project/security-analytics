
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
import org.opensearch.securityanalytics.threatIntel.common.DatasourceState;
import org.opensearch.securityanalytics.threatIntel.common.ThreatIntelLockService;

public class DatasourceRunnerTests extends ThreatIntelTestCase {
    @Before
    public void init() {
        DatasourceRunner.getJobRunnerInstance()
                .initialize(clusterService, datasourceUpdateService, datasourceDao, threatIntelExecutor, threatIntelLockService);
    }

    public void testGetJobRunnerInstance_whenCalledAgain_thenReturnSameInstance() {
        assertTrue(DatasourceRunner.getJobRunnerInstance() == DatasourceRunner.getJobRunnerInstance());
    }

    public void testRunJob_whenInvalidClass_thenThrowException() {
        JobDocVersion jobDocVersion = new JobDocVersion(randomInt(), randomInt(), randomInt());
        String jobIndexName = ThreatIntelTestHelper.randomLowerCaseString();
        String jobId = ThreatIntelTestHelper.randomLowerCaseString();
        JobExecutionContext jobExecutionContext = new JobExecutionContext(Instant.now(), jobDocVersion, lockService, jobIndexName, jobId);
        ScheduledJobParameter jobParameter = mock(ScheduledJobParameter.class);

        // Run
        expectThrows(IllegalStateException.class, () -> DatasourceRunner.getJobRunnerInstance().runJob(jobParameter, jobExecutionContext));
    }

    public void testRunJob_whenValidInput_thenSucceed() throws IOException {
        JobDocVersion jobDocVersion = new JobDocVersion(randomInt(), randomInt(), randomInt());
        String jobIndexName = ThreatIntelTestHelper.randomLowerCaseString();
        String jobId = ThreatIntelTestHelper.randomLowerCaseString();
        JobExecutionContext jobExecutionContext = new JobExecutionContext(Instant.now(), jobDocVersion, lockService, jobIndexName, jobId);
        Datasource datasource = randomDatasource();

        LockModel lockModel = randomLockModel();
        when(threatIntelLockService.acquireLock(datasource.getName(), ThreatIntelLockService.LOCK_DURATION_IN_SECONDS)).thenReturn(
                Optional.of(lockModel)
        );

        // Run
        DatasourceRunner.getJobRunnerInstance().runJob(datasource, jobExecutionContext);

        // Verify
        verify(threatIntelLockService).acquireLock(datasource.getName(), threatIntelLockService.LOCK_DURATION_IN_SECONDS);
        verify(datasourceDao).getDatasource(datasource.getName());
        verify(threatIntelLockService).releaseLock(lockModel);
    }

    public void testUpdateDatasourceRunner_whenExceptionBeforeAcquiringLock_thenNoReleaseLock() {
        ScheduledJobParameter jobParameter = mock(ScheduledJobParameter.class);
        when(jobParameter.getName()).thenReturn(ThreatIntelTestHelper.randomLowerCaseString());
        when(threatIntelLockService.acquireLock(jobParameter.getName(), ThreatIntelLockService.LOCK_DURATION_IN_SECONDS)).thenThrow(
                new RuntimeException()
        );

        // Run
        expectThrows(Exception.class, () -> DatasourceRunner.getJobRunnerInstance().updateDatasourceRunner(jobParameter).run());

        // Verify
        verify(threatIntelLockService, never()).releaseLock(any());
    }

    public void testUpdateDatasourceRunner_whenExceptionAfterAcquiringLock_thenReleaseLock() throws IOException {
        ScheduledJobParameter jobParameter = mock(ScheduledJobParameter.class);
        when(jobParameter.getName()).thenReturn(ThreatIntelTestHelper.randomLowerCaseString());
        LockModel lockModel = randomLockModel();
        when(threatIntelLockService.acquireLock(jobParameter.getName(), ThreatIntelLockService.LOCK_DURATION_IN_SECONDS)).thenReturn(
                Optional.of(lockModel)
        );
        when(datasourceDao.getDatasource(jobParameter.getName())).thenThrow(new RuntimeException());

        // Run
        DatasourceRunner.getJobRunnerInstance().updateDatasourceRunner(jobParameter).run();

        // Verify
        verify(threatIntelLockService).releaseLock(any());
    }

    public void testUpdateDatasource_whenDatasourceDoesNotExist_thenDoNothing() throws IOException {
        Datasource datasource = new Datasource();

        // Run
        DatasourceRunner.getJobRunnerInstance().updateDatasource(datasource, mock(Runnable.class));

        // Verify
        verify(datasourceUpdateService, never()).deleteUnusedIndices(any());
    }

    public void testUpdateDatasource_whenInvalidState_thenUpdateLastFailedAt() throws IOException {
        Datasource datasource = new Datasource();
        datasource.enable();
        datasource.getUpdateStats().setLastFailedAt(null);
        datasource.setState(randomStateExcept(DatasourceState.AVAILABLE));
        when(datasourceDao.getDatasource(datasource.getName())).thenReturn(datasource);

        // Run
        DatasourceRunner.getJobRunnerInstance().updateDatasource(datasource, mock(Runnable.class));

        // Verify
        assertFalse(datasource.isEnabled());
        assertNotNull(datasource.getUpdateStats().getLastFailedAt());
        verify(datasourceDao).updateDatasource(datasource);
    }

    public void testUpdateDatasource_whenValidInput_thenSucceed() throws IOException {
        Datasource datasource = randomDatasource();
        datasource.setState(DatasourceState.AVAILABLE);
        when(datasourceDao.getDatasource(datasource.getName())).thenReturn(datasource);
        Runnable renewLock = mock(Runnable.class);

        // Run
        DatasourceRunner.getJobRunnerInstance().updateDatasource(datasource, renewLock);

        // Verify
        verify(datasourceUpdateService, times(2)).deleteUnusedIndices(datasource);
        verify(datasourceUpdateService).updateOrCreateThreatIntelFeedData(datasource, renewLock);
        verify(datasourceUpdateService).updateDatasource(datasource, datasource.getSchedule(), DatasourceTask.ALL);
    }

    public void testUpdateDatasource_whenDeleteTask_thenDeleteOnly() throws IOException {
        Datasource datasource = randomDatasource();
        datasource.setState(DatasourceState.AVAILABLE);
        datasource.setTask(DatasourceTask.DELETE_UNUSED_INDICES);
        when(datasourceDao.getDatasource(datasource.getName())).thenReturn(datasource);
        Runnable renewLock = mock(Runnable.class);

        // Run
        DatasourceRunner.getJobRunnerInstance().updateDatasource(datasource, renewLock);

        // Verify
        verify(datasourceUpdateService, times(2)).deleteUnusedIndices(datasource);
        verify(datasourceUpdateService, never()).updateOrCreateThreatIntelFeedData(datasource, renewLock);
        verify(datasourceUpdateService).updateDatasource(datasource, datasource.getSchedule(), DatasourceTask.ALL);
    }

    public void testUpdateDatasourceExceptionHandling() throws IOException {
        Datasource datasource = new Datasource();
        datasource.setName(ThreatIntelTestHelper.randomLowerCaseString());
        datasource.getUpdateStats().setLastFailedAt(null);
        when(datasourceDao.getDatasource(datasource.getName())).thenReturn(datasource);
        doThrow(new RuntimeException("test failure")).when(datasourceUpdateService).deleteUnusedIndices(any());

        // Run
        DatasourceRunner.getJobRunnerInstance().updateDatasource(datasource, mock(Runnable.class));

        // Verify
        assertNotNull(datasource.getUpdateStats().getLastFailedAt());
        verify(datasourceDao).updateDatasource(datasource);
    }
}

