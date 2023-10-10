/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import static org.opensearch.securityanalytics.threatIntel.jobscheduler.DatasourceExtension.JOB_INDEX_NAME;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.jobscheduler.spi.JobDocVersion;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestHelper;
public class DatasourceExtensionTests extends ThreatIntelTestCase {
    public void testBasic() {
        DatasourceExtension extension = new DatasourceExtension();
        assertEquals("scheduler_security_analytics_threatintel_datasource", extension.getJobType());
        assertEquals(JOB_INDEX_NAME, extension.getJobIndex());
        assertEquals(DatasourceRunner.getJobRunnerInstance(), extension.getJobRunner());
    }

    public void testParser() throws Exception {
        DatasourceExtension extension = new DatasourceExtension();
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        IntervalSchedule schedule = new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS);
        String endpoint = ThreatIntelTestHelper.randomLowerCaseString();
        Datasource datasource = new Datasource(id, schedule);

        Datasource anotherDatasource = (Datasource) extension.getJobParser()
                .parse(
                        createParser(datasource.toXContent(XContentFactory.jsonBuilder(), null)),
                        ThreatIntelTestHelper.randomLowerCaseString(),
                        new JobDocVersion(randomPositiveLong(), randomPositiveLong(), randomPositiveLong())
                );

        assertTrue(datasource.equals(anotherDatasource));
    }
}
