/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.junit.After;
import org.junit.Before;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.action.FetchIocsActionResponse;
import org.opensearch.securityanalytics.model.IOC;
import org.opensearch.securityanalytics.model.IOCTests;
import org.opensearch.securityanalytics.model.IocDto;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.io.IOException;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.opensearch.securityanalytics.services.IocService.IOC_ALL_INDEX_PATTERN;

public class IocServiceIT extends OpenSearchIntegTestCase {
    private IocService service;
    private String testFeedSourceConfigId;
    private String testIndex;

    @Before
    private void beforeTest() {
        service = new IocService(client(), clusterService());
        testFeedSourceConfigId = null;
        testIndex = null;
    }

    @After
    private void afterTest() throws ExecutionException, InterruptedException {
        if (testIndex != null && !testIndex.isBlank()) {
            client().admin().indices().delete(new DeleteIndexRequest(testIndex)).get();
        }
    }

    public void test_hasIocSystemIndex_returnsFalse_whenIndexNotCreated() throws ExecutionException, InterruptedException {
        // Confirm index doesn't exist before running test case
        testFeedSourceConfigId = randomAlphaOfLength(5);
        testIndex = IocService.getFeedConfigIndexName(testFeedSourceConfigId);
        ClusterHealthResponse clusterHealthResponse = client().admin().cluster().health(new ClusterHealthRequest()).get();
        assertFalse(clusterHealthResponse.getIndices().containsKey(testIndex));

        // Run test case
        assertFalse(service.feedIndexExists(testIndex));
    }

    public void test_hasIocSystemIndex_returnsFalse_withInvalidIndex() throws ExecutionException, InterruptedException {
        // Create test index
        testFeedSourceConfigId = randomAlphaOfLength(5);
        testIndex = IocService.getFeedConfigIndexName(testFeedSourceConfigId);
        client().admin().indices().create(new CreateIndexRequest(testIndex)).get();

        // Run test case
        assertFalse(service.feedIndexExists(testIndex));
    }

    public void test_hasIocSystemIndex_returnsTrue_whenIndexExists() throws ExecutionException, InterruptedException {
        // Create test index
        testFeedSourceConfigId = randomAlphaOfLength(5);
        testIndex = IocService.getFeedConfigIndexName(testFeedSourceConfigId);
        client().admin().indices().create(new CreateIndexRequest(testIndex)).get();

        // Run test case
        assertTrue(service.feedIndexExists(testIndex));
    }

    public void test_initSystemIndexes_createsIndexes() {
        // Confirm index doesn't exist
        testFeedSourceConfigId = randomAlphaOfLength(5);
        testIndex = IocService.getFeedConfigIndexName(testFeedSourceConfigId);
        assertFalse(service.feedIndexExists(testIndex));

        // Run test case
        service.initFeedIndex(testIndex, new ActionListener<>() {
            @Override
            public void onResponse(FetchIocsActionResponse fetchIocsActionResponse) {}

            @Override
            public void onFailure(Exception e) {
                fail(String.format("Creation of %s should not fail: %s", testIndex, e));
            }
        });
        assertTrue(service.feedIndexExists(testIndex));
    }

    public void test_indexIocs_ingestsIocsCorrectly() throws IOException {
        // Prepare test IOCs
        testFeedSourceConfigId = randomAlphaOfLength(5);
        List<IOC> iocs = IntStream.range(0, randomInt())
                .mapToObj(i -> TestHelpers.randomIOC())
                .collect(Collectors.toList());

        // Run test case
        service.indexIocs(testFeedSourceConfigId, iocs, new ActionListener<>() {
            @Override
            public void onResponse(FetchIocsActionResponse fetchIocsActionResponse) {
                // Confirm expected number of IOCs in response
                assertEquals(iocs.size(), fetchIocsActionResponse.getIocs().size());

                try {
                    // Search system indexes directly
                    SearchRequest searchRequest = new SearchRequest()
                            .indices(IOC_ALL_INDEX_PATTERN)
                            .source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()));
                    SearchResponse searchResponse = client().search(searchRequest).get();

                    // Confirm expected number of hits
                    assertEquals(iocs.size(), searchResponse.getHits().getHits().length);

                    // Parse hits to IOCs
                    List<IOC> iocHits = Collections.emptyList();
                    for (SearchHit ioc : searchResponse.getHits()) {
                        try {
                            iocHits.add(IOC.parse(TestHelpers.parser(ioc.getSourceAsString()), null));
                        } catch (IOException e) {
                            fail(String.format("Failed to parse IOC hit: %s", e));
                        }
                    }

                    // Confirm expected number of IOCs
                    assertEquals(iocs.size(), iocHits.size());

                    // Sort IOCs for comparison
                    iocs.sort(Comparator.comparing(IOC::getId));
                    fetchIocsActionResponse.getIocs().sort(Comparator.comparing(IocDto::getId));
                    iocHits.sort(Comparator.comparing(IOC::getId));

                    // Confirm IOCs are equal
                    for (int i = 0; i < iocs.size(); i++) {
                        assertEqualIocs(iocs.get(i), fetchIocsActionResponse.getIocs().get(i));
                        IOCTests.assertEqualIOCs(iocs.get(i), iocHits.get(i));
                    }
                } catch (InterruptedException | ExecutionException e) {
                    fail(String.format("IOC_ALL_INDEX_PATTERN search failed: %s", e));
                }
            }

            @Override
            public void onFailure(Exception e) {
                fail(String.format("Ingestion of IOCs should not fail: %s", e));
            }
        });
    }

    private void assertEqualIocs(IOC ioc, IocDto iocDto) {
        assertEquals(ioc.getId(), iocDto.getId());
        assertEquals(ioc.getName(), iocDto.getName());
        assertEquals(ioc.getValue(), iocDto.getValue());
        assertEquals(ioc.getSeverity(), iocDto.getSeverity());
        assertEquals(ioc.getSpecVersion(), iocDto.getSpecVersion());
        assertEquals(ioc.getCreated(), iocDto.getCreated());
        assertEquals(ioc.getModified(), iocDto.getModified());
        assertEquals(ioc.getDescription(), iocDto.getDescription());
        assertEquals(ioc.getLabels(), iocDto.getLabels());
        assertEquals(ioc.getFeedId(), iocDto.getFeedId());
    }
}
