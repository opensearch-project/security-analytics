///*
// * Copyright OpenSearch Contributors
// * SPDX-License-Identifier: Apache-2.0
// */
//
//package org.opensearch.securityanalytics.resthandler;
//
//import org.junit.After;
//import org.junit.Assert;
//import org.opensearch.client.Response;
//import org.opensearch.client.WarningFailureException;
//import org.opensearch.common.settings.Settings;
//import org.opensearch.commons.alerting.model.Table;
//import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
//import org.opensearch.securityanalytics.TestHelpers;
//import org.opensearch.securityanalytics.action.ListIOCsActionRequest;
//import org.opensearch.securityanalytics.action.ListIOCsActionResponse;
//import org.opensearch.securityanalytics.commons.model.IOCType;
//import org.opensearch.securityanalytics.commons.model.STIX2;
//import org.opensearch.securityanalytics.model.STIX2IOC;
//import org.opensearch.securityanalytics.services.STIX2IOCFeedStore;
//import org.opensearch.securityanalytics.util.STIX2IOCGenerator;
//
//import java.io.IOException;
//import java.time.Instant;
//import java.util.Arrays;
//import java.util.Collections;
//import java.util.Comparator;
//import java.util.HashMap;
//import java.util.List;
//import java.util.Map;
//import java.util.stream.Collectors;
//import java.util.stream.IntStream;
//
//public class ListIOCsRestApiIT extends SecurityAnalyticsRestTestCase {
//    private final String indexMapping = "\"properties\": {\n" +
//            "    \"stix2_ioc\": {\n" +
//            "      \"dynamic\": \"false\",\n" +
//            "      \"properties\": {\n" +
//            "        \"name\": {\n" +
//            "          \"type\": \"keyword\"\n" +
//            "        },\n" +
//            "        \"type\": {\n" +
//            "          \"type\": \"keyword\"\n" +
//            "        },\n" +
//            "        \"value\": {\n" +
//            "          \"type\": \"keyword\"\n" +
//            "        },\n" +
//            "        \"severity\": {\n" +
//            "          \"type\": \"keyword\"\n" +
//            "        },\n" +
//            "        \"spec_version\": {\n" +
//            "          \"type\": \"keyword\"\n" +
//            "        },\n" +
//            "        \"created\": {\n" +
//            "          \"type\": \"date\"\n" +
//            "        },\n" +
//            "        \"modified\": {\n" +
//            "          \"type\": \"date\"\n" +
//            "        },\n" +
//            "        \"description\": {\n" +
//            "          \"type\": \"text\"\n" +
//            "        },\n" +
//            "        \"labels\": {\n" +
//            "          \"type\": \"keyword\"\n" +
//            "        },\n" +
//            "        \"feed_id\": {\n" +
//            "          \"type\": \"keyword\"\n" +
//            "        }\n" +
//            "      }\n" +
//            "    }\n" +
//            "  }";
//
//    private String testFeedSourceConfigId;
//    private String indexName;
//    ListIOCsActionRequest request;
//
//    @After
//    public void cleanUp() throws IOException {
////        deleteIndex(indexName);
//
//        testFeedSourceConfigId = null;
//        indexName = null;
//        request = null;
//    }
//
//    public void test_retrievesIOCs() throws IOException {
//        // Create index with mappings
//        testFeedSourceConfigId = TestHelpers.randomLowerCaseString();
//        indexName = STIX2IOCFeedStore.getIocIndexAlias(testFeedSourceConfigId);
//
//        try {
//            createIndex(indexName, Settings.EMPTY, indexMapping);
//        } catch (WarningFailureException warningFailureException) {
//            // Warns that index names starting with "." will be deprecated, but still creates the index
//        } catch (Exception e) {
//            fail(String.format("Test index creation failed with error: %s", e));
//        }
//
//        // Ingest IOCs
//        List<STIX2IOC> iocs = IntStream.range(0, 5)
//                .mapToObj(i -> STIX2IOCGenerator.randomIOC())
//                .collect(Collectors.toList());
//        for (STIX2IOC ioc : iocs) {
//            indexDoc(indexName, "", STIX2IOCGenerator.toJsonString(ioc));
//        }
//
//        request = new ListIOCsActionRequest(
//                Arrays.asList(ListIOCsActionRequest.ALL_TYPES_FILTER),
//                Arrays.asList(""), new Table(
//                "asc",
//                "name",
//                null,
//                iocs.size() + 1,
//                0,
//                null)
//        );
//        Map<String, String> params = new HashMap<>();
//        params.put("sortString", request.getTable().getSortString());
//        params.put("size", request.getTable().getSize() + "");
//        params.put("sortOrder", request.getTable().getSortOrder());
//        params.put("searchString", request.getTable().getSearchString() == null ? "" : request.getTable().getSearchString());
//        params.put(ListIOCsActionRequest.TYPE_FIELD, String.join(",", request.getTypes()));
//        params.put(STIX2IOC.FEED_ID_FIELD, String.join(",", request.getFeedIds()));
//
//        // Retrieve IOCs
//        Response response = makeRequest(client(), "GET", STIX2IOCGenerator.getListIOCsURI(request), params, null);
//        Assert.assertEquals(200, response.getStatusLine().getStatusCode());
//        Map<String, Object> respMap = asMap(response);
//
//        // Evaluate response
//        int totalHits = (int) respMap.get(ListIOCsActionResponse.TOTAL_HITS_FIELD);
//        assertEquals(iocs.size(), totalHits);
//
//        List<Map<String, Object>> hits = (List<Map<String, Object>>) respMap.get(ListIOCsActionResponse.HITS_FIELD);
//        assertEquals(iocs.size(), hits.size());
//
//        // Sort for easy comparison
//        iocs.sort(Comparator.comparing(STIX2IOC::getName));
//        hits.sort(Comparator.comparing(hit -> (String) hit.get(STIX2IOC.NAME_FIELD)));
//
//        for (int i = 0; i < iocs.size(); i++) {
//            Map<String, Object> hit = hits.get(i);
//            STIX2IOC newIoc = new STIX2IOC(
//                    (String) hit.get(STIX2IOC.ID_FIELD),
//                    (String) hit.get(STIX2IOC.NAME_FIELD),
//                    IOCType.valueOf((String) hit.get(STIX2IOC.TYPE_FIELD)),
//                    (String) hit.get(STIX2IOC.VALUE_FIELD),
//                    (String) hit.get(STIX2IOC.SEVERITY_FIELD),
//                    Instant.parse((String) hit.get(STIX2IOC.CREATED_FIELD)),
//                    Instant.parse((String) hit.get(STIX2IOC.MODIFIED_FIELD)),
//                    (String) hit.get(STIX2IOC.DESCRIPTION_FIELD),
//                    (List<String>) hit.get(STIX2IOC.LABELS_FIELD),
//                    (String) hit.get(STIX2IOC.SPEC_VERSION_FIELD),
//                    (String) hit.get(STIX2IOC.FEED_ID_FIELD),
//                    (String) hit.get(STIX2IOC.FEED_NAME_FIELD),
//                    Long.parseLong(String.valueOf(hit.get(STIX2IOC.VERSION_FIELD)))
//                    // TODO implement DetailedSTIX2IOCDto.NUM_FINDINGS_FIELD check when GetFindings API is added
//            );
////   fixme         STIX2IOCGenerator.assertEqualIOCs(iocs.get(i), newIoc);
//        }
//    }
//
//    // TODO: Implement additional tests using various query param combinations
//}
