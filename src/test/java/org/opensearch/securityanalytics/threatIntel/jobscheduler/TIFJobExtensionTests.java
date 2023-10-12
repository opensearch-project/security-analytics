/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import static org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobExtension.JOB_INDEX_NAME;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.jobscheduler.spi.JobDocVersion;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.TestHelpers;

public class TIFJobExtensionTests extends ThreatIntelTestCase {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    public void testBasic() {
        TIFJobExtension extension = new TIFJobExtension();
        assertEquals("scheduler_sap_threatintel_job", extension.getJobType());
        assertEquals(JOB_INDEX_NAME, extension.getJobIndex());
        assertEquals(TIFJobRunner.getJobRunnerInstance(), extension.getJobRunner());
    }

    public void testParser() throws Exception {
        TIFJobExtension extension = new TIFJobExtension();
        String id = TestHelpers.randomLowerCaseString();
        IntervalSchedule schedule = new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS);
        TIFJobParameter tifJobParameter = new TIFJobParameter(id, schedule);

        TIFJobParameter anotherTIFJobParameter = (TIFJobParameter) extension.getJobParser()
                .parse(
                        createParser(tifJobParameter.toXContent(XContentFactory.jsonBuilder(), null)),
                        TestHelpers.randomLowerCaseString(),
                        new JobDocVersion(randomPositiveLong(), randomPositiveLong(), randomPositiveLong())
                );
        log.info("first");
        log.error(tifJobParameter);
        log.error(tifJobParameter.getName());
        log.info("second");
        log.error(anotherTIFJobParameter);
        log.error(anotherTIFJobParameter.getName());

        assertTrue(tifJobParameter.getName().equals(anotherTIFJobParameter.getName()));
        assertTrue(tifJobParameter.getLastUpdateTime().equals(anotherTIFJobParameter.getLastUpdateTime()));
        assertTrue(tifJobParameter.getSchedule().equals(anotherTIFJobParameter.getSchedule()));
        assertTrue(tifJobParameter.getState().equals(anotherTIFJobParameter.getState()));
        assertTrue(tifJobParameter.getIndices().equals(anotherTIFJobParameter.getIndices()));
    }

}
