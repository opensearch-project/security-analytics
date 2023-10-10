/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.threatIntel.IT;

import org.junit.Assert;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.Datasource;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class JobRunnerIT extends ThreatIntelExtensionIntegTestCase {

    public void testJobCreateWithCorrectParams() throws IOException {
        Datasource jobParameter = new Datasource();
        jobParameter.setName("sample-job-it");
//        jobParameter.setIndexToWatch("http-logs");
        jobParameter.setSchedule(new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES));
//        jobParameter.setLockDurationSeconds(120L);

        // Creates a new watcher job.
        String jobId = OpenSearchRestTestCase.randomAlphaOfLength(10);
        Datasource schedJobParameter = createWatcherJob(jobId, jobParameter);

        // Asserts that job is created with correct parameters.
        Assert.assertEquals(jobParameter.getName(), schedJobParameter.getName());
//        Assert.assertEquals(jobParameter.getIndexToWatch(), schedJobParameter.getIndexToWatch());
        Assert.assertEquals(jobParameter.getLockDurationSeconds(), schedJobParameter.getLockDurationSeconds());
    }

    public void testJobDeleteWithDescheduleJob() throws Exception {
        String index = createTestIndex();
        Datasource jobParameter = new Datasource();
        jobParameter.setName("sample-job-it");
//        jobParameter.setIndexToWatch(index);
        jobParameter.setSchedule(new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES));
//        jobParameter.setLockDurationSeconds(120L);

        // Creates a new watcher job.
        String jobId = OpenSearchRestTestCase.randomAlphaOfLength(10);
        Datasource schedJobParameter = createWatcherJob(jobId, jobParameter);

        // wait till the job runner runs for the first time after 1 min & inserts a record into the watched index & then delete the job.
        waitAndDeleteWatcherJob(schedJobParameter.getIndexToWatch(), jobId);
        long actualCount = waitAndCountRecords(index, 130000);

        // Asserts that in the last 3 mins, no new job ran to insert a record into the watched index & all locks are deleted for the job.
        Assert.assertEquals(1, actualCount);
        Assert.assertEquals(0L, getLockTimeByJobId(jobId));
    }

    public void testJobUpdateWithRescheduleJob() throws Exception {
        String index = createTestIndex();
        Datasource jobParameter = new Datasource();
        jobParameter.setName("sample-job-it");
//        jobParameter.setIndexToWatch(index);
        jobParameter.setSchedule(new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES));
//        jobParameter.setLockDurationSeconds(120L);

        // Creates a new watcher job.
        String jobId = OpenSearchRestTestCase.randomAlphaOfLength(10);
        Datasource schedJobParameter = createWatcherJob(jobId, jobParameter);

        // update the job params to now watch a new index.
        String newIndex = createTestIndex();
//        jobParameter.setIndexToWatch(newIndex);

        // wait till the job runner runs for the first time after 1 min & inserts a record into the watched index & then update the job with
        // new params.
        waitAndCreateWatcherJob(schedJobParameter.getIndexToWatch(), jobId, jobParameter);
        long actualCount = waitAndCountRecords(newIndex, 130000);

        // Asserts that the job runner has the updated params & it inserted the record in the new watched index.
        Assert.assertEquals(1, actualCount);
        long prevIndexActualCount = waitAndCountRecords(index, 0);

        // Asserts that the job runner no longer updates the old index as the job params have been updated.
        Assert.assertEquals(1, prevIndexActualCount);
    }

    public void testAcquiredLockPreventExecOfTasks() throws Exception {
        String index = createTestIndex();
        Datasource jobParameter = new Datasource();
        jobParameter.setName("sample-job-lock-test-it");
//        jobParameter.setIndexToWatch(index);
        // ensures that the next job tries to run even before the previous job finished & released its lock. Also look at
        // SampleJobRunner.runTaskForLockIntegrationTests
        jobParameter.setSchedule(new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES));
//        jobParameter.setLockDurationSeconds(120L);

        // Creates a new watcher job.
        String jobId = OpenSearchRestTestCase.randomAlphaOfLength(10);
        createWatcherJob(jobId, jobParameter);

        // Asserts that the job runner is running for the first time & it has inserted a new record into the watched index.
        long actualCount = waitAndCountRecords(index, 80000);
        Assert.assertEquals(1, actualCount);

        // gets the lock time for the lock acquired for running first job.
        long lockTime = getLockTimeByJobId(jobId);

        // Asserts that the second job could not run & hence no new record is inserted into the watched index.
        // Also asserts that the old lock acquired for running first job is still not released.
        actualCount = waitAndCountRecords(index, 80000);
        Assert.assertEquals(1, actualCount);
        Assert.assertTrue(doesLockExistByLockTime(lockTime));

        // Asserts that the new job ran after 2 mins after the first job lock is released. Hence new record is inserted into the watched
        // index.
        // Also asserts that the old lock is released.
        actualCount = waitAndCountRecords(index, 130000);
        Assert.assertEquals(2, actualCount);
        Assert.assertFalse(doesLockExistByLockTime(lockTime));
    }
}
