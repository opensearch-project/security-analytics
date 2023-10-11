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
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;

public class TIFJobParameterTests extends ThreatIntelTestCase {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    public void testParser_whenAllValueIsFilled_thenSucceed() throws IOException {
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        IntervalSchedule schedule = new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS);
        TIFJobParameter tifJobParameter = new TIFJobParameter(id, schedule);
        tifJobParameter.enable();
        tifJobParameter.getUpdateStats().setLastProcessingTimeInMillis(randomPositiveLong());
        tifJobParameter.getUpdateStats().setLastSucceededAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));
        tifJobParameter.getUpdateStats().setLastSkippedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));
        tifJobParameter.getUpdateStats().setLastFailedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));

        TIFJobParameter anotherTIFJobParameter = TIFJobParameter.PARSER.parse(
                createParser(tifJobParameter.toXContent(XContentFactory.jsonBuilder(), null)),
                null
        );

        assertTrue(tifJobParameter.getName().equals(anotherTIFJobParameter.getName()));
        assertTrue(tifJobParameter.getLastUpdateTime().equals(anotherTIFJobParameter.getLastUpdateTime()));
        assertTrue(tifJobParameter.getEnabledTime().equals(anotherTIFJobParameter.getEnabledTime()));
        assertTrue(tifJobParameter.getSchedule().equals(anotherTIFJobParameter.getSchedule()));
        assertTrue(tifJobParameter.getState().equals(anotherTIFJobParameter.getState()));
        assertTrue(tifJobParameter.getIndices().equals(anotherTIFJobParameter.getIndices()));
        assertTrue(tifJobParameter.getUpdateStats().getLastFailedAt().equals(anotherTIFJobParameter.getUpdateStats().getLastFailedAt()));
        assertTrue(tifJobParameter.getUpdateStats().getLastSkippedAt().equals(anotherTIFJobParameter.getUpdateStats().getLastSkippedAt()));
        assertTrue(tifJobParameter.getUpdateStats().getLastSucceededAt().equals(anotherTIFJobParameter.getUpdateStats().getLastSucceededAt()));
        assertTrue(tifJobParameter.getUpdateStats().getLastProcessingTimeInMillis().equals(anotherTIFJobParameter.getUpdateStats().getLastProcessingTimeInMillis()));

    }

    public void testParser_whenNullForOptionalFields_thenSucceed() throws IOException { // TODO: same issue
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        IntervalSchedule schedule = new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS);
        TIFJobParameter tifJobParameter = new TIFJobParameter(id, schedule);
        TIFJobParameter anotherTIFJobParameter = TIFJobParameter.PARSER.parse(
                createParser(tifJobParameter.toXContent(XContentFactory.jsonBuilder(), null)),
                null
        );

        assertTrue(tifJobParameter.getName().equals(anotherTIFJobParameter.getName()));
        assertTrue(tifJobParameter.getLastUpdateTime().equals(anotherTIFJobParameter.getLastUpdateTime()));
        assertTrue(tifJobParameter.getSchedule().equals(anotherTIFJobParameter.getSchedule()));
        assertTrue(tifJobParameter.getState().equals(anotherTIFJobParameter.getState()));
        assertTrue(tifJobParameter.getIndices().equals(anotherTIFJobParameter.getIndices()));
    }

    public void testCurrentIndexName_whenNotExpired_thenReturnName() {
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setName(id);
    }

    public void testNewIndexName_whenCalled_thenReturnedExpectedValue() {
        TIFMetadata tifMetadata = new TIFMetadata("mock_id",
                "mock url",
                "mock name",
                "mock org",
                "mock description",
                "mock csv",
                List.of("mock ip"),
                1,
                false);

        String name = tifMetadata.getFeedId();
        String suffix = "1";
        TIFJobParameter tifJobParameter = new TIFJobParameter();
        tifJobParameter.setName(name);
        assertEquals(String.format(Locale.ROOT, "%s-%s-%s", THREAT_INTEL_DATA_INDEX_NAME_PREFIX, name, suffix), tifJobParameter.newIndexName(tifJobParameter,tifMetadata));
        tifJobParameter.getIndices().add(tifJobParameter.newIndexName(tifJobParameter,tifMetadata));

        log.error(tifJobParameter.getIndices());

        String anotherSuffix = "2";
        assertEquals(String.format(Locale.ROOT, "%s-%s-%s", THREAT_INTEL_DATA_INDEX_NAME_PREFIX, name, anotherSuffix), tifJobParameter.newIndexName(tifJobParameter,tifMetadata));
    }

    public void testLockDurationSeconds() {
        TIFJobParameter datasource = new TIFJobParameter();
        assertNotNull(datasource.getLockDurationSeconds());
    }
}

