/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.resthandler;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.opensearch.client.Response;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.commons.utils.testUtils.S3ObjectGenerator;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.services.STIX2IOCFeedStore;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.model.Source;
import org.opensearch.securityanalytics.util.STIX2IOCGenerator;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.JOB_INDEX_NAME;

/**
 * The following system parameters must be specified to successfully run these tests:
 *
 * tests.SATIFSourceConfigRestApiIT.bucketName - the name of the S3 bucket to use for the tests
 * tests.SATIFSourceConfigRestApiIT.region - the AWS region of the S3 bucket
 * tests.SATIFSourceConfigRestApiIT.roleArn - the IAM role ARN to assume when making S3 calls
 *
 * The local system must have sufficient credentials to write to S3, delete from S3, and assume the provided role.
 *
 * These tests are disabled by default as there is no default value for the tests.s3connector.bucket system property. This is
 * intentional as the tests will fail when run without the proper setup, such as during CI workflows.
 *
 * Example command to manually run this class's ITs:
 * ./gradlew ':integTest' --tests "org.opensearch.securityanalytics.resthandler.SATIFSourceConfigRestApiIT" \
 * -Dtests.SATIFSourceConfigRestApiIT.bucketName=<BUCKET_NAME> \
 * -Dtests.SATIFSourceConfigRestApiIT.region=<REGION> \
 * -Dtests.SATIFSourceConfigRestApiIT.roleArn=<ROLE_ARN>
 */
@EnabledIfSystemProperty(named = "tests.SATIFSourceConfigRestApiIT.bucketName", matches = ".+")
public class SATIFSourceConfigRestApiIT extends SecurityAnalyticsRestTestCase {

    private String bucketName;
    private String objectKey;
    private String region;
    private String roleArn;
    private Source source;
    private S3Client s3Client;
    private S3ObjectGenerator s3ObjectGenerator;
    private STIX2IOCGenerator stix2IOCGenerator;

    @Before
    public void initSource() {
        // Retrieve system parameters needed to run the tests
        if (bucketName == null) {
            bucketName = System.getProperty("tests.SATIFSourceConfigRestApiIT.bucketName");
            region = System.getProperty("tests.SATIFSourceConfigRestApiIT.region");
            roleArn = System.getProperty("tests.SATIFSourceConfigRestApiIT.roleArn");
        }

        // Only create the s3Client once
        if (bucketName != null && s3Client == null) {
            s3Client = S3Client.builder()
                    .region(Region.of(region))
                    .build();
            s3ObjectGenerator = new S3ObjectGenerator(s3Client, bucketName);
        }

        // Refresh source for each test
        objectKey = TestHelpers.randomLowerCaseString();
        source = new S3Source(bucketName, objectKey, region, roleArn);
    }

    @After
    public void afterTest() {
        s3Client.close();
    }

    public void testCreateSATIFSourceConfigAndVerifyJobRan() throws IOException, InterruptedException {
        // Generate test IOCs, and upload them to S3 to create the bucket object. Feed creation fails if the bucket object doesn't exist.
        int numOfIOCs = 1;
        stix2IOCGenerator = new STIX2IOCGenerator();
        s3ObjectGenerator.write(numOfIOCs, objectKey, stix2IOCGenerator);
        assertEquals("Incorrect number of test IOCs generated.", numOfIOCs, stix2IOCGenerator.getIocs().size());

        // Create test feed
        String feedName = "test_feed_name";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
        List<String> iocTypes = List.of("ip", "domain");

        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
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
                true,
                iocTypes
        );
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
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
        String firstUpdatedTime = (String) ((Map<String, Object>)responseBody.get("source_config")).get("last_update_time");

        // wait for job runner to run
        waitUntil(() -> {
            try {
                return verifyJobRan(createdId, firstUpdatedTime);
            } catch (IOException e) {
                throw new RuntimeException("failed to verify that job ran");
            }
        }, 240, TimeUnit.SECONDS);
    }

    /**
     * Calls the get source config api and checks if the last updated time is different from the time that was passed in
     * @param createdId
     * @param firstUpdatedTime
     * @return
     * @throws IOException
     */
    protected boolean verifyJobRan(String createdId, String firstUpdatedTime) throws IOException {
        Response response;
        Map<String, Object> responseBody;

        // call get API to get the latest source config by ID
        response = makeRequest(client(), "GET", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI + "/" + createdId, Collections.emptyMap(), null);
        responseBody = asMap(response);

        String returnedLastUpdatedTime = (String) ((Map<String, Object>)responseBody.get("source_config")).get("last_update_time");

        if(firstUpdatedTime.equals(returnedLastUpdatedTime.toString()) == false) {
            return true;
        }
        return false;
    }

    public void testGetSATIFSourceConfigById() throws IOException {
        // Generate test IOCs, and upload them to S3 to create the bucket object. Feed creation fails if the bucket object doesn't exist.
        int numOfIOCs = 1;
        stix2IOCGenerator = new STIX2IOCGenerator();
        s3ObjectGenerator.write(numOfIOCs, objectKey, stix2IOCGenerator);
        assertEquals("Incorrect number of test IOCs generated.", numOfIOCs, stix2IOCGenerator.getIocs().size());

        // Create test feed
        String feedName = "test_feed_name";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        List<String> iocTypes = List.of("hash");

        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
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
                true,
                iocTypes
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
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

        String returnedFeedName = (String) ((Map<String, Object>)responseBody.get("source_config")).get("name");
        Assert.assertEquals("Created feed name and returned feed name do not match", feedName, returnedFeedName);

        String returnedFeedFormat = (String) ((Map<String, Object>)responseBody.get("source_config")).get("format");
        Assert.assertEquals("Created feed format and returned feed format do not match", feedFormat, returnedFeedFormat);

        String returnedFeedType = (String) ((Map<String, Object>)responseBody.get("source_config")).get("type");
        Assert.assertEquals("Created feed type and returned feed type do not match", sourceConfigType, SATIFSourceConfigDto.toSourceConfigType(returnedFeedType));

        List<String> returnedIocTypes = (List<String>) ((Map<String, Object>)responseBody.get("source_config")).get("ioc_types");
        Assert.assertTrue("Created ioc types and returned ioc types do not match", iocTypes.containsAll(returnedIocTypes) && returnedIocTypes.containsAll(iocTypes));
    }

    public void testDeleteSATIFSourceConfig() throws IOException {
        // Generate test IOCs, and upload them to S3 to create the bucket object. Feed creation fails if the bucket object doesn't exist.
        int numOfIOCs = 1;
        stix2IOCGenerator = new STIX2IOCGenerator();
        s3ObjectGenerator.write(numOfIOCs, objectKey, stix2IOCGenerator);
        assertEquals("Incorrect number of test IOCs generated.", numOfIOCs, stix2IOCGenerator.getIocs().size());

        // Create test feed
        String feedName = "test_feed_name";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
        List<String> iocTypes = List.of("ip", "hash");

        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
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
                true,
                iocTypes
        );

        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
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

    public void testRetrieveIOCsSuccessfully() throws IOException, InterruptedException {
        // Generate test IOCs, and upload them to S3
        int numOfIOCs = 5;
        stix2IOCGenerator = new STIX2IOCGenerator();
        stix2IOCGenerator.setType(IOCType.ip);
        s3ObjectGenerator.write(numOfIOCs, objectKey, stix2IOCGenerator);
        assertEquals("Incorrect number of test IOCs generated.", numOfIOCs, stix2IOCGenerator.getIocs().size());

        // Create test feed
        String feedName = "download_test_feed_name";
        String feedFormat = "STIX";
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
        List<String> iocTypes = List.of(IOCType.ip.toString());

        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
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
                true,
                iocTypes
        );

        // Confirm test feed was created successfully
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(response);

        String createdId = responseBody.get("_id").toString();
        Assert.assertNotEquals("Response is missing Id", SATIFSourceConfigDto.NO_ID, createdId);


        // Wait for feed to execute
        String firstUpdatedTime = (String) ((Map<String, Object>)responseBody.get("source_config")).get("last_refreshed_time");
        waitUntil(() -> {
            try {
                return verifyJobRan(createdId, firstUpdatedTime);
            } catch (IOException e) {
                throw new RuntimeException("failed to verify that job ran");
            }
        }, 240, TimeUnit.SECONDS);

        // Confirm IOCs were ingested to system index for the feed
        String indexName = STIX2IOCFeedStore.getIocIndexAlias(createdId);
        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(indexName, request);

        // Confirm expected number of results are returned
        assertEquals(numOfIOCs, hits.size());
        List<Map<String, Object>> iocs = hits.stream()
                .map(SearchHit::getSourceAsMap)
                .collect(Collectors.toList());

        // Sort IOC lists for easy comparison
        stix2IOCGenerator.getIocs().sort(Comparator.comparing(STIX2IOC::getName));
        iocs.sort(Comparator.comparing(ioc -> (String) ioc.get(STIX2IOC.NAME_FIELD)));

        // Confirm expected IOCs have been ingested
        for (int i = 0; i < numOfIOCs; i++) {
            assertEquals(stix2IOCGenerator.getIocs().get(i).getName(), iocs.get(i).get(STIX2IOC.NAME_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getType().toString(), iocs.get(i).get(STIX2IOC.TYPE_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getValue(), iocs.get(i).get(STIX2IOC.VALUE_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getSeverity(), iocs.get(i).get(STIX2IOC.SEVERITY_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getCreated().toString(), iocs.get(i).get(STIX2IOC.CREATED_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getModified().toString(), iocs.get(i).get(STIX2IOC.MODIFIED_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getDescription(), iocs.get(i).get(STIX2IOC.DESCRIPTION_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getLabels(), iocs.get(i).get(STIX2IOC.LABELS_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getFeedId(), iocs.get(i).get(STIX2IOC.FEED_ID_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getSpecVersion(), iocs.get(i).get(STIX2IOC.SPEC_VERSION_FIELD));
        }
    }
}
