/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import static org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobExtension.JOB_INDEX_NAME;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.jobscheduler.spi.JobDocVersion;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestHelper;
public class TIFJobExtensionTests extends ThreatIntelTestCase {
    public void testBasic() {
        TIFJobExtension extension = new TIFJobExtension();
        assertEquals("scheduler_sap_threatintel_job", extension.getJobType());
        assertEquals(JOB_INDEX_NAME, extension.getJobIndex());
        assertEquals(TIFJobRunner.getJobRunnerInstance(), extension.getJobRunner());
    }

    public void testParser() throws Exception {
        TIFJobExtension extension = new TIFJobExtension();
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        IntervalSchedule schedule = new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS);
        String endpoint = ThreatIntelTestHelper.randomLowerCaseString();
        TIFJobParameter datasource = new TIFJobParameter(id, schedule);

        TIFJobParameter anotherDatasource = (TIFJobParameter) extension.getJobParser()
                .parse(
                        createParser(datasource.toXContent(XContentFactory.jsonBuilder(), null)),
                        ThreatIntelTestHelper.randomLowerCaseString(),
                        new JobDocVersion(randomPositiveLong(), randomPositiveLong(), randomPositiveLong())
                );

        assertTrue(datasource.equals(anotherDatasource));
    }
}
