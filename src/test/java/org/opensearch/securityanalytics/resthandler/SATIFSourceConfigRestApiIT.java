/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.model.Source;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.JOB_INDEX_NAME;

public class SATIFSourceConfigRestApiIT extends SecurityAnalyticsRestTestCase {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigRestApiIT.class);
    public void testCreateSATIFSourceConfigAndVerifyJobRan() throws IOException, InterruptedException {
        String feedName = "test_feed_name";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
        List<String> iocTypes = List.of("ip", "dns");
        Source source = new S3Source("bucket", "objectkey", "region", "rolearn");

        SATIFSourceConfigDto SaTifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                feedName,
                feedFormat,
                sourceConfigType,
                null,
                null,
                Instant.now(),
                source,
                null,
                Instant.now(),
                schedule,
                null,
                null,
                Instant.now(),
                null,
                false,
                iocTypes
        );
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(SaTifSourceConfigDto));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        String createdId = responseBody.get("_id").toString();
        Assert.assertNotEquals("response is missing Id", SATIFSourceConfigDto.NO_ID, createdId);

        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, createdId), response.getHeader("Location"));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(JOB_INDEX_NAME, request);
        Assert.assertEquals(1, hits.size());

        // call get API to get the latest source config by ID
        response = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/" + createdId, Collections.emptyMap(), null);
        responseBody = asMap(response);
        String firstUpdatedTime = (String) ((Map<String, Object>)responseBody.get("tif_config")).get("last_update_time");

        // wait for job runner to run
        waitUntil(() -> {
            try {
                return verifyJobRan(createdId, firstUpdatedTime);
            } catch (IOException e) {
                throw new RuntimeException("failed to verify that job ran");
            }
        }, 240, TimeUnit.SECONDS);
    }

    protected boolean verifyJobRan(String createdId, String firstUpdatedTime) throws IOException {
        Response response;
        Map<String, Object> responseBody;

        // call get API to get the latest source config by ID
        response = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/" + createdId, Collections.emptyMap(), null);
        responseBody = asMap(response);

        String returnedLastUpdatedTime = (String) ((Map<String, Object>)responseBody.get("tif_config")).get("last_update_time");

        if(firstUpdatedTime.equals(returnedLastUpdatedTime.toString()) == false) {
            return true;
        }
        return false;
    }


    public void testGetSATIFSourceConfigById() throws IOException {
        String feedName = "test_feed_name";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        Source source = new S3Source("bucket", "objectkey", "region", "rolearn");
        List<String> iocTypes = List.of("hash");

        SATIFSourceConfigDto SaTifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                feedName,
                feedFormat,
                sourceConfigType,
                null,
                null,
                Instant.now(),
                source,
                null,
                Instant.now(),
                schedule,
                null,
                null,
                Instant.now(),
                null,
                false,
                iocTypes
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(SaTifSourceConfigDto));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        String createdId = responseBody.get("_id").toString();
        Assert.assertNotEquals("response is missing Id", SATIFSourceConfigDto.NO_ID, createdId);

        response = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/" + createdId, Collections.emptyMap(), null);
        responseBody = asMap(response);

        String responseId = responseBody.get("_id").toString();
        Assert.assertEquals("Created Id and returned Id do not match", createdId, responseId);

        int responseVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertTrue("Incorrect version", responseVersion > 0);

        String returnedFeedName = (String) ((Map<String, Object>)responseBody.get("tif_config")).get("feed_name");
        Assert.assertEquals("Created feed name and returned feed name do not match", feedName, returnedFeedName);

        String returnedFeedFormat = (String) ((Map<String, Object>)responseBody.get("tif_config")).get("feed_format");
        Assert.assertEquals("Created feed format and returned feed format do not match", feedFormat, returnedFeedFormat);

        String returnedFeedType = (String) ((Map<String, Object>)responseBody.get("tif_config")).get("feed_type");
        Assert.assertEquals("Created feed type and returned feed type do not match", sourceConfigType, SATIFSourceConfigDto.toFeedType(returnedFeedType));

        List<String> returnedIocTypes = (List<String>) ((Map<String, Object>)responseBody.get("tif_config")).get("ioc_types");
        Assert.assertTrue("Created ioc types and returned ioc types do not match", iocTypes.containsAll(returnedIocTypes) && returnedIocTypes.containsAll(iocTypes));
    }

    public void testDeleteSATIFSourceConfig() throws IOException {
        String feedName = "test_feed_name";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        Source source = new S3Source("bucket", "objectkey", "region", "rolearn");
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
        List<String> iocTypes = List.of("ip", "dns");

        SATIFSourceConfigDto SaTifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                feedName,
                feedFormat,
                sourceConfigType,
                null,
                null,
                Instant.now(),
                source,
                null,
                Instant.now(),
                schedule,
                null,
                null,
                Instant.now(),
                null,
                false,
                iocTypes
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(SaTifSourceConfigDto));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        String createdId = responseBody.get("_id").toString();
        Assert.assertNotEquals("response is missing Id", SATIFSourceConfigDto.NO_ID, createdId);

        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, createdId), response.getHeader("Location"));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(JOB_INDEX_NAME, request);
        Assert.assertEquals(1, hits.size());

        // call delete API to delete the threat intel source config
        response = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/" + createdId, Collections.emptyMap(), null);
        Assert.assertEquals(200, response.getStatusLine().getStatusCode());
        responseBody = asMap(response);

        String deletedId = responseBody.get("_id").toString();
        Assert.assertEquals(deletedId, createdId);

        hits = executeSearch(JOB_INDEX_NAME, request);
        Assert.assertEquals(0, hits.size());
    }
}
