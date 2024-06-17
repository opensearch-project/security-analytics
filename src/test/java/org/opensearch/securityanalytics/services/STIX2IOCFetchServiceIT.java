/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.commons.connector.model.S3ConnectorConfig;
import org.opensearch.securityanalytics.commons.utils.testUtils.S3ObjectGenerator;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.util.STIX2IOCGenerator;
import org.opensearch.test.OpenSearchIntegTestCase;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import java.io.IOException;
import java.util.Locale;
import java.util.UUID;

public class STIX2IOCFetchServiceIT extends OpenSearchIntegTestCase {
    private String bucket;
    private String region;
    private String roleArn;

    private S3Client s3Client;
    private S3ObjectGenerator s3ObjectGenerator;
    private STIX2IOCFetchService service;

    private String testFeedSourceConfigId;
    private String testIndex;
    private S3ConnectorConfig s3ConnectorConfig;

    @Before
    public void beforeTest() {
        if (service == null) {
            region = System.getProperty("tests.STIX2IOCFetchServiceIT.region");
            roleArn = System.getProperty("tests.STIX2IOCFetchServiceIT.roleArn");
            bucket = System.getProperty("tests.STIX2IOCFetchServiceIT.bucket");

            s3Client = S3Client.builder()
                    .region(Region.of(region))
                    .build();
            s3ObjectGenerator = new S3ObjectGenerator(s3Client, bucket);

            service = new STIX2IOCFetchService();
        }
        testFeedSourceConfigId = UUID.randomUUID().toString();
        testIndex = null;
        s3ConnectorConfig = new S3ConnectorConfig(bucket, testFeedSourceConfigId, region, roleArn);
    }

    @After
    private void afterTest() {
        if (testIndex != null && !testIndex.isBlank()) {
            client().delete(new DeleteRequest(testIndex));
        }
    }

    @Test
    public void test_fetchIocs_fetchesIocsCorrectly() throws IOException {
        int numOfIOCs = 5;
        s3ObjectGenerator.write(numOfIOCs, testFeedSourceConfigId, new STIX2IOCGenerator());

        ActionListener<STIX2IOCFetchService.STIX2IOCFetchResponse> listener = new ActionListener<>() {
            @Override
            public void onResponse(STIX2IOCFetchService.STIX2IOCFetchResponse stix2IOCFetchResponse) {
                assertEquals(numOfIOCs, stix2IOCFetchResponse.getIocs().size());
                //TODO hurneyt need to retrieve the test IOCs from s3ObjectGenerator.write, and compare to output
            }

            @Override
            public void onFailure(Exception e) {
                fail("STIX2IOCFetchService.fetchIocs failed with error: " + e);
            }
        };

        service.fetchIocs(s3ConnectorConfig, listener);
    }


    // TODO hurneyt extract feedIndexExists and initFeedIndex to helper function, or expose for testing
//    @Test
//    public void test_hasIocSystemIndex_returnsFalse_whenIndexNotCreated() throws ExecutionException, InterruptedException {
//        // Confirm index doesn't exist before running test case
//        testIndex = STIX2IOCFeedStore.getFeedConfigIndexName(testFeedSourceConfigId);
//        ClusterHealthResponse clusterHealthResponse = client().admin().cluster().health(new ClusterHealthRequest()).get();
//        assertFalse(clusterHealthResponse.getIndices().containsKey(testIndex));
//
//        // Run test case
//        assertFalse(service.feedIndexExists(testIndex));
//    }
//
//    @Test
//    public void test_hasIocSystemIndex_returnsFalse_withInvalidIndex() throws ExecutionException, InterruptedException {
//        // Create test index
//        testIndex = STIX2IOCFeedStore.getFeedConfigIndexName(testFeedSourceConfigId);
//        client().admin().indices().create(new CreateIndexRequest(testIndex)).get();
//
//        // Run test case
//        assertFalse(service.feedIndexExists(testIndex));
//    }
//
//    @Test
//    public void test_hasIocSystemIndex_returnsTrue_whenIndexExists() throws ExecutionException, InterruptedException {
//        // Create test index
//        testIndex = STIX2IOCFeedStore.getFeedConfigIndexName(testFeedSourceConfigId);
//        client().admin().indices().create(new CreateIndexRequest(testIndex)).get();
//
//        // Run test case
//        assertTrue(service.feedIndexExists(testIndex));
//    }
//
//    @Test
//    public void test_initSystemIndexes_createsIndexes() {
//        // Confirm index doesn't exist
//        testIndex = IocService.getFeedConfigIndexName(testFeedSourceConfigId);
//        assertFalse(service.feedIndexExists(testIndex));
//
//        // Run test case
//        service.initFeedIndex(testIndex, new ActionListener<>() {
//            @Override
//            public void onResponse(FetchIocsActionResponse fetchIocsActionResponse) {}
//
//            @Override
//            public void onFailure(Exception e) {
//                fail(String.format("Creation of %s should not fail: %s", testIndex, e));
//            }
//        });
//        assertTrue(service.feedIndexExists(testIndex));
//    }
//
//    @Test
//    public void test_indexIocs_ingestsIocsCorrectly() throws IOException {
//        // Prepare test IOCs
//        List<STIX2IOC> iocs = IntStream.range(0, randomInt())
//                .mapToObj(i -> STIX2IOCGenerator.randomIOC())
//                .collect(Collectors.toList());
//
//        // Run test case
//        service.indexIocs(testFeedSourceConfigId, iocs, new ActionListener<>() {
//            @Override
//            public void onResponse(FetchIocsActionResponse fetchIocsActionResponse) {
//                // Confirm expected number of IOCs in response
//                assertEquals(iocs.size(), fetchIocsActionResponse.getIocs().size());
//
//                try {
//                    // Search system indexes directly
//                    SearchRequest searchRequest = new SearchRequest()
//                            .indices(IOC_ALL_INDEX_PATTERN)
//                            .source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()));
//                    SearchResponse searchResponse = client().search(searchRequest).get();
//
//                    // Confirm expected number of hits
//                    assertEquals(iocs.size(), searchResponse.getHits().getHits().length);
//
//                    // Parse hits to IOCs
//                    List<IocModel> iocHits = Collections.emptyList();
//                    for (SearchHit ioc : searchResponse.getHits()) {
//                        try {
//                            iocHits.add(IocModel.parse(TestHelpers.parser(ioc.getSourceAsString()), null));
//                        } catch (IOException e) {
//                            fail(String.format("Failed to parse IOC hit: %s", e));
//                        }
//                    }
//
//                    // Confirm expected number of IOCs
//                    assertEquals(iocs.size(), iocHits.size());
//
//                    // Sort IOCs for comparison
//                    iocs.sort(Comparator.comparing(IocModel::getId));
//                    fetchIocsActionResponse.getIocs().sort(Comparator.comparing(IocDto::getId));
//                    iocHits.sort(Comparator.comparing(IocModel::getId));
//
//                    // Confirm IOCs are equal
//                    for (int i = 0; i < iocs.size(); i++) {
//                        assertEqualIocs(iocs.get(i), fetchIocsActionResponse.getIocs().get(i));
//                        IocModelTests.assertEqualIOCs(iocs.get(i), iocHits.get(i));
//                    }
//                } catch (InterruptedException | ExecutionException e) {
//                    fail(String.format("IOC_ALL_INDEX_PATTERN search failed: %s", e));
//                }
//            }
//
//            @Override
//            public void onFailure(Exception e) {
//                fail(String.format("Ingestion of IOCs should not fail: %s", e));
//            }
//        });
//    }

    private String createEndpointString() {
        return STIX2IOCServiceTestAPI.RestSTIX2IOCServiceTestAPIAction.ROUTE + String.format(Locale.getDefault(),
                "?%s=%s&%s=%s&%s=%s&%s=%s",
                STIX2IOCServiceTestAPI.STIX2IOCServiceTestAPIRequest.BUCKET_FIELD,
                bucket,
                STIX2IOCServiceTestAPI.STIX2IOCServiceTestAPIRequest.REGION_FIELD,
                region,
                STIX2IOCServiceTestAPI.STIX2IOCServiceTestAPIRequest.ROLE_ARN_FIELD,
                roleArn,
                STIX2IOCServiceTestAPI.STIX2IOCServiceTestAPIRequest.OBJECT_KEY_FIELD,
                testFeedSourceConfigId
        );
    }
}
