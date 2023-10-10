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

import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestHelper;

public class TIFJobParameterTests extends ThreatIntelTestCase {

    public void testParser_whenAllValueIsFilled_thenSucceed() throws IOException {
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        IntervalSchedule schedule = new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS);
//        String endpoint = ThreatIntelTestHelper.randomLowerCaseString();
        List<String> stringList = new ArrayList<>();
        stringList.add("ip");

        TIFJobParameter tifJobParameter = new TIFJobParameter(id, schedule);
        tifJobParameter.enable();
        tifJobParameter.setCurrentIndex(ThreatIntelTestHelper.randomLowerCaseString());
        tifJobParameter.getDatabase().setFields(Arrays.asList("field1", "field2"));
        tifJobParameter.getDatabase().setFeedId("test123");
        tifJobParameter.getDatabase().setFeedName("name");
        tifJobParameter.getDatabase().setFeedFormat("csv");
        tifJobParameter.getDatabase().setEndpoint("url");
        tifJobParameter.getDatabase().setDescription("test description");
        tifJobParameter.getDatabase().setOrganization("test org");
        tifJobParameter.getDatabase().setContained_iocs_field(stringList);
        tifJobParameter.getDatabase().setIocCol("0");

        tifJobParameter.getUpdateStats().setLastProcessingTimeInMillis(randomPositiveLong());
        tifJobParameter.getUpdateStats().setLastSucceededAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));
        tifJobParameter.getUpdateStats().setLastSkippedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));
        tifJobParameter.getUpdateStats().setLastFailedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));

        TIFJobParameter anotherTIFJobParameter = TIFJobParameter.PARSER.parse(
                createParser(tifJobParameter.toXContent(XContentFactory.jsonBuilder(), null)),
                null
        );
        assertTrue(tifJobParameter.equals(anotherTIFJobParameter));
    }

    public void testParser_whenNullForOptionalFields_thenSucceed() throws IOException {
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        IntervalSchedule schedule = new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS);
//        String endpoint = ThreatIntelTestHelper.randomLowerCaseString();
        TIFJobParameter datasource = new TIFJobParameter(id, schedule);
        TIFJobParameter anotherDatasource = TIFJobParameter.PARSER.parse(
                createParser(datasource.toXContent(XContentFactory.jsonBuilder(), null)),
                null
        );
        assertTrue(datasource.equals(anotherDatasource));
    }

    public void testCurrentIndexName_whenNotExpired_thenReturnName() {
        List<String> stringList = new ArrayList<>();
        stringList.add("ip");

        String id = ThreatIntelTestHelper.randomLowerCaseString();
        Instant now = Instant.now();
        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setName(id);
        datasource.setCurrentIndex(datasource.newIndexName(ThreatIntelTestHelper.randomLowerCaseString()));
        datasource.getDatabase().setFeedId("test123");
        datasource.getDatabase().setFeedName("name");
        datasource.getDatabase().setFeedFormat("csv");
        datasource.getDatabase().setEndpoint("url");
        datasource.getDatabase().setDescription("test description");
        datasource.getDatabase().setOrganization("test org");
        datasource.getDatabase().setContained_iocs_field(stringList);
        datasource.getDatabase().setIocCol("0");
        datasource.getDatabase().setFields(new ArrayList<>());

        assertNotNull(datasource.currentIndexName());
    }

    public void testNewIndexName_whenCalled_thenReturnedExpectedValue() {
        String name = ThreatIntelTestHelper.randomLowerCaseString();
        String suffix = ThreatIntelTestHelper.randomLowerCaseString();
        TIFJobParameter datasource = new TIFJobParameter();
        datasource.setName(name);
        assertEquals(String.format(Locale.ROOT, "%s.%s.%s", THREAT_INTEL_DATA_INDEX_NAME_PREFIX, name, suffix), datasource.newIndexName(suffix));
    }

    public void testResetDatabase_whenCalled_thenNullifySomeFields() {
        TIFJobParameter datasource = randomDatasource();
        assertNotNull(datasource.getDatabase().getFeedId());
        assertNotNull(datasource.getDatabase().getFeedName());
        assertNotNull(datasource.getDatabase().getFeedFormat());
        assertNotNull(datasource.getDatabase().getEndpoint());
        assertNotNull(datasource.getDatabase().getDescription());
        assertNotNull(datasource.getDatabase().getOrganization());
        assertNotNull(datasource.getDatabase().getContained_iocs_field());
        assertNotNull(datasource.getDatabase().getIocCol());

        // Run
        datasource.resetDatabase();

        // Verify
        assertNull(datasource.getDatabase().getFeedId());
        assertNull(datasource.getDatabase().getFeedName());
        assertNull(datasource.getDatabase().getFeedFormat());
        assertNull(datasource.getDatabase().getEndpoint());
        assertNull(datasource.getDatabase().getDescription());
        assertNull(datasource.getDatabase().getOrganization());
        assertNull(datasource.getDatabase().getContained_iocs_field());
        assertNull(datasource.getDatabase().getIocCol());
    }

    public void testLockDurationSeconds() {
        TIFJobParameter datasource = new TIFJobParameter();
        assertNotNull(datasource.getLockDurationSeconds());
    }
}

