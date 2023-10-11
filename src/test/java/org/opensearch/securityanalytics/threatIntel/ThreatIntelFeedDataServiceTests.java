///*
// * Copyright OpenSearch Contributors
// * SPDX-License-Identifier: Apache-2.0
// */
//
//package org.opensearch.securityanalytics.threatIntel;
//
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.Mockito.mock;
//import static org.mockito.Mockito.never;
//import static org.mockito.Mockito.times;
//import static org.mockito.Mockito.verify;
//import static org.mockito.Mockito.when;
//
//import java.io.File;
//import java.io.FileInputStream;
//import java.net.URLConnection;
//import java.nio.ByteBuffer;
//import java.nio.charset.StandardCharsets;
//import java.time.Instant;
//import java.util.*;
//
//
//import org.apache.commons.csv.CSVFormat;
//import org.apache.commons.csv.CSVParser;
//import org.apache.commons.csv.CSVRecord;
//import org.apache.lucene.search.TotalHits;
//import org.junit.Before;
//import org.opensearch.OpenSearchException;
//import org.opensearch.action.admin.indices.create.CreateIndexRequest;
//import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
//import org.opensearch.action.admin.indices.forcemerge.ForceMergeRequest;
//import org.opensearch.action.admin.indices.refresh.RefreshRequest;
//import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
//import org.opensearch.action.bulk.BulkRequest;
//import org.opensearch.action.bulk.BulkResponse;
//import org.opensearch.action.search.SearchRequest;
//import org.opensearch.action.search.SearchResponse;
//import org.opensearch.action.support.master.AcknowledgedResponse;
//import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
//import org.opensearch.cluster.routing.Preference;
//import org.opensearch.common.SuppressForbidden;
//import org.opensearch.core.common.bytes.BytesReference;
//import org.opensearch.index.query.QueryBuilders;
//import org.opensearch.search.SearchHit;
//import org.opensearch.search.SearchHits;
//import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;
//
//@SuppressForbidden(reason = "unit test")
//public class ThreatIntelFeedDataServiceTests extends ThreatIntelTestCase {
//    private static final String IP_RANGE_FIELD_NAME = "_cidr";
//    private static final String DATA_FIELD_NAME = "_data";
//    private ThreatIntelFeedDataService noOpsGeoIpDataDao;
//    private ThreatIntelFeedDataService verifyingGeoIpDataDao;
//
//    @Before
//    public void init() {
//        noOpsGeoIpDataDao = new ThreatIntelFeedDataService(clusterService, client, new IndexNameExpressionResolver(), xContentRegistry(),);
//        verifyingGeoIpDataDao = new ThreatIntelFeedDataService(clusterService, verifyingClient);
//    }
//
//    public void testCreateIndexIfNotExistsWithExistingIndex() {
//        String index = ThreatIntelTestHelper.randomLowerCaseString();
//        when(metadata.hasIndex(index)).thenReturn(true);
//        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> { throw new RuntimeException("Shouldn't get called"); });
//        verifyingGeoIpDataDao.createIndexIfNotExists(index);
//    }
//
//    public void testCreateIndexIfNotExistsWithoutExistingIndex() {
//        String index = ThreatIntelTestHelper.randomLowerCaseString();
//        when(metadata.hasIndex(index)).thenReturn(false);
//        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
//            assertTrue(actionRequest instanceof CreateIndexRequest);
//            CreateIndexRequest request = (CreateIndexRequest) actionRequest;
//            assertEquals(index, request.index());
//            assertEquals(1, (int) request.settings().getAsInt("index.number_of_shards", 0));
//            assertNull(request.settings().get("index.auto_expand_replicas"));
//            assertEquals(0, (int) request.settings().getAsInt("index.number_of_replicas", 1));
//            assertEquals(-1, (int) request.settings().getAsInt("index.refresh_interval", 0));
//            assertEquals(true, request.settings().getAsBoolean("index.hidden", false));
//
//            assertEquals(
//                "{\"dynamic\": false,\"properties\": {\"_cidr\": {\"type\": \"ip_range\",\"doc_values\": false}}}",
//                request.mappings()
//            );
//            return null;
//        });
//        verifyingGeoIpDataDao.createIndexIfNotExists(index);
//    }
//
//    public void testGetDatabaseReader() throws Exception {
//        File zipFile = new File(this.getClass().getClassLoader().getResource("threatIntel/sample_valid.zip").getFile());
//        List<String> containedIocs = new ArrayList<>();
//        containedIocs.add("ip");
//        TIFMetadata tifMetadata = new TIFMetadata("id", "https://reputation.alienvault.com/reputation.generic", "name", "org", "desc", "type", containedIocs, 0, false);
//
//        CSVParser parser = ThreatIntelFeedParser.getThreatIntelFeedReaderCSV(tifMetadata);
//        String[] expectedHeader = { "network", "country_name" };
//        assertArrayEquals(expectedHeader, parser.iterator().next().values());
//        String[] expectedValues = { "1.0.0.0/24", "Australia" };
//        assertArrayEquals(expectedValues, parser.iterator().next().values());
//    }
//
////    public void testGetDatabaseReaderNoFile() throws Exception {
////        File zipFile = new File(this.getClass().getClassLoader().getResource("ip2geo/sample_valid.zip").getFile());
////        DatasourceManifest manifest = new DatasourceManifest(
////            zipFile.toURI().toURL().toExternalForm(),
////            "no_file.csv",
////            "fake_sha256",
////            1l,
////            Instant.now().toEpochMilli(),
////            "tester"
////        );
////        Exception exception = expectThrows(IllegalArgumentException.class, () -> noOpsGeoIpDataDao.getDatabaseReader(manifest));
////        assertTrue(exception.getMessage().contains("does not exist"));
////    }
////
////    @SneakyThrows
////    public void testInternalGetDatabaseReader_whenCalled_thenSetUserAgent() {
////        File zipFile = new File(this.getClass().getClassLoader().getResource("ip2geo/sample_valid.zip").getFile());
////        DatasourceManifest manifest = new DatasourceManifest(
////            zipFile.toURI().toURL().toExternalForm(),
////            "sample_valid.csv",
////            "fake_sha256",
////            1l,
////            Instant.now().toEpochMilli(),
////            "tester"
////        );
////
////        URLConnection connection = mock(URLConnection.class);
////        when(connection.getInputStream()).thenReturn(new FileInputStream(zipFile));
////
////        // Run
////        noOpsGeoIpDataDao.internalGetDatabaseReader(manifest, connection);
////
////        // Verify
////        verify(connection).addRequestProperty(Constants.USER_AGENT_KEY, Constants.USER_AGENT_VALUE);
////    }
////
////    public void testDeleteIp2GeoDataIndex_whenCalled_thenDeleteIndex() {
////        String index = String.format(Locale.ROOT, "%s.%s", IP2GEO_DATA_INDEX_NAME_PREFIX, ThreatIntelTestHelper.randomLowerCaseString());
////        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
////            assertTrue(actionRequest instanceof DeleteIndexRequest);
////            DeleteIndexRequest request = (DeleteIndexRequest) actionRequest;
////            assertEquals(1, request.indices().length);
////            assertEquals(index, request.indices()[0]);
////            return new AcknowledgedResponse(true);
////        });
////        verifyingGeoIpDataDao.deleteIp2GeoDataIndex(index);
////    }
////
////    public void testDeleteIp2GeoDataIndexWithNonIp2GeoDataIndex() {
////        String index = ThreatIntelTestHelper.randomLowerCaseString();
////        Exception e = expectThrows(OpenSearchException.class, () -> verifyingGeoIpDataDao.deleteIp2GeoDataIndex(index));
////        assertTrue(e.getMessage().contains("not ip2geo data index"));
////        verify(verifyingClient, never()).index(any());
////    }
////
////    @SneakyThrows
////    public void testPutGeoIpData_whenValidInput_thenSucceed() {
////        String index = ThreatIntelTestHelper.randomLowerCaseString();
////        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
////            if (actionRequest instanceof BulkRequest) {
////                BulkRequest request = (BulkRequest) actionRequest;
////                assertEquals(2, request.numberOfActions());
////                BulkResponse response = mock(BulkResponse.class);
////                when(response.hasFailures()).thenReturn(false);
////                return response;
////            } else if (actionRequest instanceof RefreshRequest) {
////                RefreshRequest request = (RefreshRequest) actionRequest;
////                assertEquals(1, request.indices().length);
////                assertEquals(index, request.indices()[0]);
////                return null;
////            } else if (actionRequest instanceof ForceMergeRequest) {
////                ForceMergeRequest request = (ForceMergeRequest) actionRequest;
////                assertEquals(1, request.indices().length);
////                assertEquals(index, request.indices()[0]);
////                assertEquals(1, request.maxNumSegments());
////                return null;
////            } else if (actionRequest instanceof UpdateSettingsRequest) {
////                UpdateSettingsRequest request = (UpdateSettingsRequest) actionRequest;
////                assertEquals(1, request.indices().length);
////                assertEquals(index, request.indices()[0]);
////                assertEquals(true, request.settings().getAsBoolean("index.blocks.write", false));
////                assertNull(request.settings().get("index.num_of_replica"));
////                assertEquals("0-all", request.settings().get("index.auto_expand_replicas"));
////                return null;
////            } else {
////                throw new RuntimeException("invalid request is called");
////            }
////        });
////        Runnable renewLock = mock(Runnable.class);
////        try (CSVParser csvParser = CSVParser.parse(sampleIp2GeoFile(), StandardCharsets.UTF_8, CSVFormat.RFC4180)) {
////            Iterator<CSVRecord> iterator = csvParser.iterator();
////            String[] fields = iterator.next().values();
////            verifyingGeoIpDataDao.putGeoIpData(index, fields, iterator, renewLock);
////            verify(renewLock, times(2)).run();
////        }
////    }
////
////    public void testGetGeoIpData_whenDataExist_thenReturnTheData() {
////        String indexName = ThreatIntelTestHelper.randomLowerCaseString();
////        String ip = randomIpAddress();
////        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
////            assert actionRequest instanceof SearchRequest;
////            SearchRequest request = (SearchRequest) actionRequest;
////            assertEquals(Preference.LOCAL.type(), request.preference());
////            assertEquals(1, request.source().size());
////            assertEquals(QueryBuilders.termQuery(IP_RANGE_FIELD_NAME, ip), request.source().query());
////
////            String data = String.format(
////                Locale.ROOT,
////                "{\"%s\":\"1.0.0.1/16\",\"%s\":{\"city\":\"seattle\"}}",
////                IP_RANGE_FIELD_NAME,
////                DATA_FIELD_NAME
////            );
////            SearchHit searchHit = new SearchHit(1);
////            searchHit.sourceRef(BytesReference.fromByteBuffer(ByteBuffer.wrap(data.getBytes(StandardCharsets.UTF_8))));
////            SearchHit[] searchHitArray = { searchHit };
////            SearchHits searchHits = new SearchHits(searchHitArray, new TotalHits(1l, TotalHits.Relation.EQUAL_TO), 1);
////
////            SearchResponse response = mock(SearchResponse.class);
////            when(response.getHits()).thenReturn(searchHits);
////            return response;
////        });
////
////        // Run
////        Map<String, Object> geoData = verifyingGeoIpDataDao.getGeoIpData(indexName, ip);
////
////        // Verify
////        assertEquals("seattle", geoData.get("city"));
////    }
//}
