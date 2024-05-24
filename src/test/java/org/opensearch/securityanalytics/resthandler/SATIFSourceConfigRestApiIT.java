/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.threatIntel.common.FeedType;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.JOB_INDEX_NAME;

public class SATIFSourceConfigRestApiIT extends SecurityAnalyticsRestTestCase {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigRestApiIT.class);
    public void testCreateSATIFSourceConfig() throws IOException {
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);

        SATIFSourceConfigDto satifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                "feedname",
                "stix",
                FeedType.CUSTOM,
                null,
                null,
                null,
                null,
                schedule,
                null,
                null,
                null,
                null,
                true,
                null,
                List.of("ip", "dns")
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.TIF_SOURCE_CONFIG_URI, Collections.emptyMap(), toHttpEntity(satifSourceConfigDto));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        String createdId = responseBody.get("_id").toString();
        Assert.assertNotEquals("response is missing Id", SATIFSourceConfigDto.NO_ID, createdId);

        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.TIF_SOURCE_CONFIG_URI, createdId), response.getHeader("Location"));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(JOB_INDEX_NAME, request);
        Assert.assertEquals(1, hits.size());
    }
}
