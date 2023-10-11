/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.threatIntel.integTests;

import org.junit.Assert;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameter;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class ThreatIntelIT extends SecurityAnalyticsRestTestCase {

//    public void testJobCreateWithCorrectParams() throws IOException {
//        TIFJobParameter jobParameter = new TIFJobParameter();
//        jobParameter.setName("threat-intel-job");
//        jobParameter.setSchedule(new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES));
//
//        // Creates a new watcher job.
//        String jobId = OpenSearchRestTestCase.randomAlphaOfLength(10);
//        TIFJobParameter schedJobParameter = createWatcherJob(jobId, jobParameter);
//
//        // Asserts that job is created with correct parameters.
//        Assert.assertEquals(jobParameter.getName(), schedJobParameter.getName());
//        Assert.assertEquals(jobParameter.getLockDurationSeconds(), schedJobParameter.getLockDurationSeconds());
//    }

//    public void testJobDeleteWithDescheduleJob() throws Exception {
//        String index = createTestIndex();
//        TIFJobParameter jobParameter = new TIFJobParameter();
//        jobParameter.setName("threat-intel-job");
//        jobParameter.setSchedule(new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES));
//
//        // Creates a new watcher job.
//        String jobId = OpenSearchRestTestCase.randomAlphaOfLength(10);
//        TIFJobParameter schedJobParameter = createWatcherJob(jobId, jobParameter);
//
//        // wait till the job runner runs for the first time after 1 min & inserts a record into the watched index & then delete the job.
//        waitAndDeleteWatcherJob(schedJobParameter.getIndexToWatch(), jobId);
//        long actualCount = waitAndCountRecords(index, 130000);
//
//        // Asserts that in the last 3 mins, no new job ran to insert a record into the watched index & all locks are deleted for the job.
//        Assert.assertEquals(1, actualCount);
//        Assert.assertEquals(0L, getLockTimeByJobId(jobId));
//    }
}

