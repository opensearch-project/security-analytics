/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import static org.opensearch.securityanalytics.threatIntel.jobscheduler.Datasource.THREAT_INTEL_DATA_INDEX_NAME_PREFIX;

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

public class DatasourceTests extends ThreatIntelTestCase {

    public void testParser_whenAllValueIsFilled_thenSucceed() throws IOException {
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        IntervalSchedule schedule = new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS);
//        String endpoint = ThreatIntelTestHelper.randomLowerCaseString();
        List<String> stringList = new ArrayList<>();
        stringList.add("ip");

        Datasource datasource = new Datasource(id, schedule);
        datasource.enable();
        datasource.setCurrentIndex(ThreatIntelTestHelper.randomLowerCaseString());
        datasource.getDatabase().setFields(Arrays.asList("field1", "field2"));
        datasource.getDatabase().setFeedId("test123");
        datasource.getDatabase().setFeedName("name");
        datasource.getDatabase().setFeedFormat("csv");
        datasource.getDatabase().setEndpoint("url");
        datasource.getDatabase().setDescription("test description");
        datasource.getDatabase().setOrganization("test org");
        datasource.getDatabase().setContained_iocs_field(stringList);
        datasource.getDatabase().setIocCol("0");

        datasource.getUpdateStats().setLastProcessingTimeInMillis(randomPositiveLong());
        datasource.getUpdateStats().setLastSucceededAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));
        datasource.getUpdateStats().setLastSkippedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));
        datasource.getUpdateStats().setLastFailedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS));

        Datasource anotherDatasource = Datasource.PARSER.parse(
                createParser(datasource.toXContent(XContentFactory.jsonBuilder(), null)),
                null
        );
        assertTrue(datasource.equals(anotherDatasource));
    }

    public void testParser_whenNullForOptionalFields_thenSucceed() throws IOException {
        String id = ThreatIntelTestHelper.randomLowerCaseString();
        IntervalSchedule schedule = new IntervalSchedule(Instant.now().truncatedTo(ChronoUnit.MILLIS), 1, ChronoUnit.DAYS);
//        String endpoint = ThreatIntelTestHelper.randomLowerCaseString();
        Datasource datasource = new Datasource(id, schedule);
        Datasource anotherDatasource = Datasource.PARSER.parse(
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
        Datasource datasource = new Datasource();
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
        Datasource datasource = new Datasource();
        datasource.setName(name);
        assertEquals(String.format(Locale.ROOT, "%s.%s.%s", THREAT_INTEL_DATA_INDEX_NAME_PREFIX, name, suffix), datasource.newIndexName(suffix));
    }

    public void testResetDatabase_whenCalled_thenNullifySomeFields() {
        Datasource datasource = randomDatasource();
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
        Datasource datasource = new Datasource();
        assertNotNull(datasource.getLockDurationSeconds());
    }
}

