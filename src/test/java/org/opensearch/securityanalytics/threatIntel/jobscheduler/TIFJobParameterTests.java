/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import static org.opensearch.securityanalytics.threatIntel.jobscheduler.TIFJobParameter.THREAT_INTEL_DATA_INDEX_NAME_PREFIX;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestHelper;

public class TIFJobParameterTests extends ThreatIntelTestCase {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    public void testParser_whenAllValueIsFilled_thenSucceed() throws IOException {  // TODO: same issue
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        IntervalSchedule schedule = new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS);
        TIFJobParameter tifJobParameter = new TIFJobParameter(id, schedule);
        tifJobParameter.enable();
        tifJobParameter.setCurrentIndex(ThreatIntelTestHelper.randomLowerCaseString());
        tifJobParameter.getUpdateStats().setLastProcessingTimeInMillis(randomPositiveLong());
        tifJobParameter.getUpdateStats().setLastSucceededAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));
        tifJobParameter.getUpdateStats().setLastSkippedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));
        tifJobParameter.getUpdateStats().setLastFailedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));

        TIFJobParameter anotherTIFJobParameter = TIFJobParameter.PARSER.parse(
                createParser(tifJobParameter.toXContent(XContentFactory.jsonBuilder(), null)),
                null
        );

        log.info("first");
        log.error(tifJobParameter);
        log.error(tifJobParameter.getName());
        log.error(tifJobParameter.getCurrentIndex());
        log.info("second");
        log.error(anotherTIFJobParameter);
        log.error(anotherTIFJobParameter.getName());
        log.error(anotherTIFJobParameter.getCurrentIndex());

        assertTrue(tifJobParameter.equals(anotherTIFJobParameter));
    }

    public void testParser_whenNullForOptionalFields_thenSucceed() throws IOException { // TODO: same issue
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        IntervalSchedule schedule = new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS);
        TIFJobParameter datasource = new TIFJobParameter(id, schedule);
        TIFJobParameter anotherDatasource = TIFJobParameter.PARSER.parse(
                createParser(datasource.toXContent(XContentFactory.jsonBuilder(), null)),
                null
        );
        assertTrue(datasource.equals(anotherDatasource));
    }

    public void testCurrentIndexName_whenNotExpired_thenReturnName() {
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setName(id);
        datasource.setCurrentIndex(datasource.newIndexName(ThreatIntelTestHelper.randomLowerCaseString()));

        assertNotNull(datasource.currentIndexName());
    }

    public void testNewIndexName_whenCalled_thenReturnedExpectedValue() {
        String name = ThreatIntelTestHelper.randomLowerCaseString();
        String suffix = ThreatIntelTestHelper.randomLowerCaseString();
        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setName(name);
        assertEquals(String.format(Locale.ROOT, "%s.%s.%s", THREAT_INTEL_DATA_INDEX_NAME_PREFIX, name, suffix), datasource.newIndexName(suffix));
    }

    public void testLockDurationSeconds() {
        TIFJobParameter datasource = new TIFJobParameter();
        assertNotNull(datasource.getLockDurationSeconds());
    }
}

