/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.resthandler;

import com.google.common.collect.ImmutableList;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.commons.utils.testUtils.S3ObjectGenerator;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.model.Source;
import org.opensearch.securityanalytics.util.STIX2IOCGenerator;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.JOB_INDEX_NAME;
import static org.opensearch.securityanalytics.services.STIX2IOCFeedStore.getAllIocIndexPatternById;

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
 *
 * Optionally, the following system parameter can be supplied to PREVENT the tests from cleaning up the bucket objects.
 * This could be helpful when troubleshooting failing tests by investigating the data generated during execution.
 * By default, the bucket objects (not the bucket) will be cleaned up after the tests.
 * To disable cleanup, add the following system parameter.
 * -Dtests.SATIFSourceConfigRestApiIT.cleanup=false
 */
public class SATIFSourceConfigRestApiIT extends SecurityAnalyticsRestTestCase {

    private String bucketName;
    private String objectKey;
    private String region;
    private String roleArn;
    private Source source;
    private S3Client s3Client;
    private S3ObjectGenerator s3ObjectGenerator;
    private STIX2IOCGenerator stix2IOCGenerator;

    /**
     * Is reassigned in the initSource function.
     * Will only be TRUE if 'bucketName', 'region', and 'roleArn' are supplied through system params.
     * Disables tests when FALSE.
     */
    private boolean canRunTests;

    /**
     * List of invalid type patterns for easy test execution
     */
    private final List<String> invalidTypes = ImmutableList.of(
            "ip", // "ip" is not currently a supported IOCType
            "ipv4_addr" // Currently, the supported IOCTypes do not contain underscores
    );

    @Before
    public void initSource() {
        // Retrieve system parameters needed to run the tests. Only retrieve once
        if (bucketName == null) {
            bucketName = System.getProperty("tests.SATIFSourceConfigRestApiIT.bucketName");
            region = System.getProperty("tests.SATIFSourceConfigRestApiIT.region");
            roleArn = System.getProperty("tests.SATIFSourceConfigRestApiIT.roleArn");
        }

        // Confirm necessary system params are provided
        canRunTests = bucketName != null && !bucketName.isBlank() &&
                region != null && !region.isBlank() &&
                roleArn != null && !roleArn.isBlank();

        // Exit test setup if necessary system params are not provided
        if (!canRunTests) {
            logger.info(getClass().getName() + " tests disabled.");
            System.out.println(getClass().getName() + " tests disabled.");
            return;
        }

        // Only create the s3Client once
        if (s3Client == null) {
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
        // Exit test cleanup if necessary system params are not provided
        if (!canRunTests) return;

        // Delete the bucket object unless cleanup is disabled
        if (!Objects.equals(System.getProperty("tests.SATIFSourceConfigRestApiIT.cleanup"), "false")) {
            DeleteObjectResponse response =  s3Client.deleteObject(
                    DeleteObjectRequest.builder()
                            .bucket(bucketName)
                            .key(objectKey)
                            .build()
            );

            // Confirm bucket object was deleted successfully
            assertTrue(
                    String.format("Failed to delete object with key %s in bucket %s", objectKey, bucketName),
                    response.sdkHttpResponse().isSuccessful()
            );
        }

        // Close the client
        s3Client.close();
    }

    public void testCreateSATIFSourceConfigAndVerifyJobRan() throws IOException, InterruptedException {
        // Only run tests when required system params are provided
        if (!canRunTests) return;

        // Generate test IOCs, and upload them to S3 to create the bucket object. Feed creation fails if the bucket object doesn't exist.
        int numOfIOCs = 1;
        stix2IOCGenerator = new STIX2IOCGenerator(List.of(new IOCType(IOCType.IPV4_TYPE)));
        s3ObjectGenerator.write(numOfIOCs, objectKey, stix2IOCGenerator);
        assertEquals("Incorrect number of test IOCs generated.", numOfIOCs, stix2IOCGenerator.getIocs().size());

        // Create test feed
        String feedName = "test_feed_name";
        String feedFormat = "STIX2";
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.DOMAIN_NAME_TYPE);

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
                iocTypes,
                true
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

    public void testGetSATIFSourceConfigById() throws IOException {
        // Only run tests when required system params are provided
        if (!canRunTests) return;

        // Generate test IOCs, and upload them to S3 to create the bucket object. Feed creation fails if the bucket object doesn't exist.
        int numOfIOCs = 1;
        stix2IOCGenerator = new STIX2IOCGenerator(List.of(new IOCType(IOCType.HASHES_TYPE)));
        s3ObjectGenerator.write(numOfIOCs, objectKey, stix2IOCGenerator);
        assertEquals("Incorrect number of test IOCs generated.", numOfIOCs, stix2IOCGenerator.getIocs().size());

        // Create test feed
        String feedName = "test_feed_name";
        String feedFormat = "STIX2";
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.DAYS);
        List<String> iocTypes = List.of(IOCType.HASHES_TYPE);

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
                iocTypes,
                true
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
        // Only run tests when required system params are provided
        if (!canRunTests) return;

        // Generate test IOCs, and upload them to S3 to create the bucket object. Feed creation fails if the bucket object doesn't exist.
        int numOfIOCs = 1;
        stix2IOCGenerator = new STIX2IOCGenerator(List.of(new IOCType(IOCType.IPV4_TYPE)));
        s3ObjectGenerator.write(numOfIOCs, objectKey, stix2IOCGenerator);
        assertEquals("Incorrect number of test IOCs generated.", numOfIOCs, stix2IOCGenerator.getIocs().size());

        // Create test feed
        String feedName = "test_feed_name";
        String feedFormat = "STIX2";
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
        List<String> iocTypes = List.of(IOCType.IPV4_TYPE, IOCType.HASHES_TYPE);

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
                iocTypes,
                true
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
        // Only run tests when required system params are provided
        if (!canRunTests) return;

        // Execute test for each IOCType
        for (String type : IOCType.types()) {
            // Generate test IOCs, and upload them to S3
            int numOfIOCs = 5;
            stix2IOCGenerator = new STIX2IOCGenerator(List.of(new IOCType(type)));
            s3ObjectGenerator.write(numOfIOCs, objectKey, stix2IOCGenerator);
            assertEquals("Incorrect number of test IOCs generated for type: " + type, numOfIOCs, stix2IOCGenerator.getIocs().size());

            // Create test feed
            String feedName = "download_test_feed_name";
            String feedFormat = "STIX2";
            SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
            IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
            List<String> iocTypes = List.of(type);

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
                iocTypes,
                true
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
        String indexName = getAllIocIndexPatternById(createdId);
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
                assertEquals(stix2IOCGenerator.getIocs().get(i).getType().getType(), IOCType.fromString((String) iocs.get(i).get(STIX2IOC.TYPE_FIELD)));
                assertEquals(stix2IOCGenerator.getIocs().get(i).getValue(), iocs.get(i).get(STIX2IOC.VALUE_FIELD));
                assertEquals(stix2IOCGenerator.getIocs().get(i).getSeverity(), iocs.get(i).get(STIX2IOC.SEVERITY_FIELD));

                // TODO troubleshoot instant assertions
//            assertEquals(stix2IOCGenerator.getIocs().get(i).getCreated().toString(), iocs.get(i).get(STIX2IOC.CREATED_FIELD));
//            assertEquals(stix2IOCGenerator.getIocs().get(i).getModified().toString(), iocs.get(i).get(STIX2IOC.MODIFIED_FIELD));

                assertEquals(stix2IOCGenerator.getIocs().get(i).getDescription(), iocs.get(i).get(STIX2IOC.DESCRIPTION_FIELD));
                assertEquals(stix2IOCGenerator.getIocs().get(i).getLabels(), iocs.get(i).get(STIX2IOC.LABELS_FIELD));
                assertEquals(createdId, iocs.get(i).get(STIX2IOC.FEED_ID_FIELD));
                assertEquals(stix2IOCGenerator.getIocs().get(i).getSpecVersion(), iocs.get(i).get(STIX2IOC.SPEC_VERSION_FIELD));
            }
        }
    }

    public void testRetrieveMultipleIOCTypesSuccessfully() throws IOException, InterruptedException {
        // Only run tests when required system params are provided
        if (!canRunTests) return;

        // Generate test IOCs for each type, and upload them to S3
        int numOfIOCs = 5;
        stix2IOCGenerator = new STIX2IOCGenerator();
        s3ObjectGenerator.write(numOfIOCs, objectKey, stix2IOCGenerator);
        List<STIX2IOC> allIocs = stix2IOCGenerator.getIocs();
        assertEquals("Incorrect total number of test IOCs generated.", IOCType.types().size() * numOfIOCs, allIocs.size());

        // Create test feed
        String feedName = "download_test_feed_name";
        String feedFormat = "STIX2";
        SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
        IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);

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
                IOCType.types(),
                true
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
        String indexName = getAllIocIndexPatternById(createdId);

        String request = "{\n" +
                "   \"size\" : 10000,\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(indexName, request);

        // Confirm expected number of results are returned
        assertEquals(allIocs.size(), hits.size());
        List<Map<String, Object>> iocHits = hits.stream()
                .map(SearchHit::getSourceAsMap)
                .collect(Collectors.toList());

        // Sort IOC lists for easy comparison
        allIocs.sort(Comparator.comparing(STIX2IOC::getName));
        iocHits.sort(Comparator.comparing(ioc -> (String) ioc.get(STIX2IOC.NAME_FIELD)));

        // Confirm expected IOCs have been ingested
        for (int i = 0; i < allIocs.size(); i++) {
            assertEquals(stix2IOCGenerator.getIocs().get(i).getName(), iocHits.get(i).get(STIX2IOC.NAME_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getType(), IOCType.fromString((String) iocHits.get(i).get(STIX2IOC.TYPE_FIELD)));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getValue(), iocHits.get(i).get(STIX2IOC.VALUE_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getSeverity(), iocHits.get(i).get(STIX2IOC.SEVERITY_FIELD));

            // TODO troubleshoot instant assertions
//            assertEquals(stix2IOCGenerator.getIocs().get(i).getCreated().toString(), iocHits.get(i).get(STIX2IOC.CREATED_FIELD));
//            assertEquals(stix2IOCGenerator.getIocs().get(i).getModified().toString(), iocHits.get(i).get(STIX2IOC.MODIFIED_FIELD));

            assertEquals(stix2IOCGenerator.getIocs().get(i).getDescription(), iocHits.get(i).get(STIX2IOC.DESCRIPTION_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getLabels(), iocHits.get(i).get(STIX2IOC.LABELS_FIELD));
            assertEquals(createdId, iocHits.get(i).get(STIX2IOC.FEED_ID_FIELD));
            assertEquals(stix2IOCGenerator.getIocs().get(i).getSpecVersion(), iocHits.get(i).get(STIX2IOC.SPEC_VERSION_FIELD));
        }
    }

    public void testWithValidAndInvalidIOCTypes() throws IOException {
        // Only run tests when required system params are provided
        if (!canRunTests) return;

        // Generate test IOCs, and upload them to S3
        int numOfIOCs = 5;
        stix2IOCGenerator = new STIX2IOCGenerator(List.of(new IOCType(IOCType.IPV4_TYPE)));
        s3ObjectGenerator.write(numOfIOCs, objectKey, stix2IOCGenerator);
        assertEquals("Incorrect number of test IOCs generated.", numOfIOCs, stix2IOCGenerator.getIocs().size());

        List<String> types = new ArrayList<>(invalidTypes);
        types.addAll(IOCType.types());

        // Execute the test for each invalid type
        for (String type : invalidTypes) {
            // Create test feed
            String feedName = "download_test_feed_name";
            String feedFormat = "STIX2";
            SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
            IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);

            List<String> iocTypes = List.of(type);

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
                    iocTypes,
                    true
            );

            Exception exception = assertThrows(ResponseException.class, () ->
                    makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto))
            );

            String expectedError = "{\"error\":{\"root_cause\":[{\"type\":\"status_exception\",\"reason\":\"No compatible Iocs were downloaded for config download_test_feed_name\"}],\"type\":\"status_exception\",\"reason\":\"No compatible Iocs were downloaded for config download_test_feed_name\"},\"status\":400}";
            assertTrue(exception.getMessage().contains(expectedError));
        }
    }

    public void testWithInvalidIOCTypes() throws IOException {
        // Only run tests when required system params are provided
        if (!canRunTests) return;

        // Generate test IOCs, and upload them to S3
        int numOfIOCs = 5;
        stix2IOCGenerator = new STIX2IOCGenerator(List.of(new IOCType(IOCType.IPV4_TYPE)));
        s3ObjectGenerator.write(numOfIOCs, objectKey, stix2IOCGenerator);
        assertEquals("Incorrect number of test IOCs generated.", numOfIOCs, stix2IOCGenerator.getIocs().size());

        // Execute the test for each invalid type
        for (String type : invalidTypes) {
            // Create test feed
            String feedName = "download_test_feed_name";
            String feedFormat = "STIX2";
            SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
            IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);

            List<String> iocTypes = List.of(type);

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
                    iocTypes,
                    true
            );

            Exception exception = assertThrows(ResponseException.class, () ->
                    makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto))
            );

            String expectedError = "{\"error\":{\"root_cause\":[{\"type\":\"status_exception\",\"reason\":\"No compatible Iocs were downloaded for config download_test_feed_name\"}],\"type\":\"status_exception\",\"reason\":\"No compatible Iocs were downloaded for config download_test_feed_name\"},\"status\":400}";
            assertTrue(exception.getMessage().contains(expectedError));
        }
    }

    public void testWithNoIOCsToDownload() {
        // Only run tests when required system params are provided
        if (!canRunTests) return;

        // Create the bucket object without any IOCs
        PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                .bucket(bucketName)
                .key(objectKey)
                .build();
        PutObjectResponse putObjectResponse = s3Client.putObject(putObjectRequest, RequestBody.empty());
        assertTrue("Failed to create empty bucket object for type.", putObjectResponse.sdkHttpResponse().isSuccessful());

        // Execute the test case for each IOC type
        for (String type : IOCType.types()) {
            // Create test feed
            String feedName = "download_test_feed_name";
            String feedFormat = "STIX2";
            SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
            IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
            List<String> iocTypes = List.of(type);

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
                    iocTypes,
                    true
            );

            Exception exception = assertThrows(ResponseException.class, () ->
                    makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto))
            );

            String expectedError = "{\"error\":{\"root_cause\":[{\"type\":\"status_exception\",\"reason\":\"No compatible Iocs were downloaded for config download_test_feed_name\"}],\"type\":\"status_exception\",\"reason\":\"No compatible Iocs were downloaded for config download_test_feed_name\"},\"status\":400}";
            assertTrue(exception.getMessage().contains(expectedError));
        }
    }

    public void testWhenBucketObjectDoesNotExist() {
        // Only run tests when required system params are provided
        if (!canRunTests) return;

        // Confirm bucket object does not exist
        HeadObjectRequest headObjectRequest = HeadObjectRequest.builder()
                .bucket(bucketName)
                .key(objectKey)
                .build();
        assertThrows(
                String.format("Object %s in bucket %s should not exist.", objectKey, bucketName),
                NoSuchKeyException.class, () -> s3Client.headObject(headObjectRequest)
        );

        // Execute the test case for each IOC type
        for (String type : IOCType.types()) {
            // Create test feed
            String feedName = "download_test_feed_name";
            String feedFormat = "STIX2";
            SourceConfigType sourceConfigType = SourceConfigType.S3_CUSTOM;
            IntervalSchedule schedule = new IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES);
            List<String> iocTypes = List.of(type);

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
                    iocTypes,
                    true
            );

            Exception exception = assertThrows(ResponseException.class, () ->
                    makeRequest(client(), "POST", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, Collections.emptyMap(), toHttpEntity(saTifSourceConfigDto))
            );

            String expectedError = "{\"error\":{\"root_cause\":[{\"type\":\"no_such_key_exception\",\"reason\":\"The specified key does not exist.";
            assertTrue("Exception contains unexpected message: " + exception.getMessage(), exception.getMessage().contains(expectedError));
        }
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

        String returnedLastUpdatedTime = (String) ((Map<String, Object>) responseBody.get("source_config")).get("last_update_time");

        if(firstUpdatedTime.equals(returnedLastUpdatedTime.toString()) == false) {
            return true;
        }
        return false;
    }
}
