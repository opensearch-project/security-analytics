/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import static org.opensearch.securityanalytics.TestHelpers.randomAggregationRule;
import static org.opensearch.securityanalytics.TestHelpers.randomDetector;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.randomRule;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.commons.alerting.model.Monitor.MonitorType;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Detector.DetectorType;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.Rule;

public class DetectorMonitorRestApiIT extends SecurityAnalyticsRestTestCase {
    /**
     * 1. Creates detector with 5 doc prepackaged level rules and one doc level monitor based on the given rules
     * 2. Creates two aggregation rules and assigns to a detector, while removing 5 prepackaged rules
     * 3. Verifies that two bucket level monitor exists
     * 4. Verifies the findings
     * @throws IOException
     */
    public void testRemoveDocLevelRuleAddAggregationRules_verifyFindings_success() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        Detector detector = randomDetector(getRandomPrePackagedRules());

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals("Number of total hits not correct", 5, response.getHits().getTotalHits().value);

        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();
        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";

        // Verify that one document level monitor is created
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, Object> detectorAsMap = (Map<String, Object>) hit.getSourceAsMap().get("detector");
        List<String> monitorIds = (List<String>) (detectorAsMap).get("monitor_id");

        assertEquals("Number of monitors not correct", 1, monitorIds.size());

        String monitorId = monitorIds.get(0);
        String monitorType  = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");

        assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

        // Create aggregation rules
        String sumRuleId = createRule(randomAggregationRule( "sum", " > 2"), "test_windows");
        String avgTermRuleId = createRule(randomAggregationRule( "avg", " > 1"), "test_windows");
        // Update detector and empty doc level rules so detector contains only one aggregation rule
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(sumRuleId), new DetectorRule(avgTermRuleId)),
            Collections.emptyList(), Collections.emptyList());
        Detector updatedDetector = randomDetectorWithInputs(List.of(input));

        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        Map<String, Object> updateResponseBody = asMap(updateResponse);
        detectorId = updateResponseBody.get("_id").toString();

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorAsMap = (Map<String, Object>) hit.getSourceAsMap().get("detector");
        monitorIds = (List<String>) (detectorAsMap).get("monitor_id");

        assertEquals(2, monitorIds.size());

        indexDoc(index, "1", randomDoc(2, 4, "Info"));
        indexDoc(index, "2", randomDoc(3, 4, "Info"));

        // Execute two bucket level monitors
        for(String id: monitorIds){
            monitorType  = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + id))).get("monitor")).get("monitor_type");

            assertEquals("Invalid monitor type", MonitorType.BUCKET_LEVEL_MONITOR.getValue(), monitorType);

            executeAlertingMonitor(id, Collections.emptyMap());
        }
        // verify bucket level monitor findings
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        assertEquals(2, getFindingsBody.get("total_findings"));

        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");
        for(Map<String, Object> finding : findings) {
            Set<String> aggRulesFinding = ((List<Map<String, Object>>) finding.get("queries")).stream().map(it -> it.get("id").toString()).collect(
                Collectors.toSet());
            // Bucket monitor finding will have one rule
            String aggRuleId = aggRulesFinding.iterator().next();

            assertTrue(aggRulesFinding.contains(aggRuleId));

            List<String> findingDocs = (List<String>)finding.get("related_doc_ids");
            assertEquals("Number of found document not correct", 2, findingDocs.size());
            assertTrue(Arrays.asList("1", "2").containsAll(findingDocs));
        }

        String findingDetectorId = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals("Detector id is not as expected", detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);
    }

    /**
     * 1. Creates detector with 1 aggregation rule and one bucket level monitor based on the aggregation rule
     * 2. Creates 5 prepackaged doc level rules and one custom doc level rule and removes the aggregation rule
     * 3. Verifies that one doc level monitor exists
     * 4. Verifies the findings
     * @throws IOException
     */
    public void testReplaceAggregationRuleWithDocRule_verifyFindings_success() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        String maxRuleId = createRule(randomAggregationRule( "max", " > 2"), "test_windows");
        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList(), Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();
        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(Rule.CUSTOM_RULES_INDEX, request, true);

        assertEquals("Number of custom rules not correct",1, response.getHits().getTotalHits().value);

        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";
        // Verify that one bucket level monitor is created
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, Object> detectorAsMap = (Map<String, Object>) hit.getSourceAsMap().get("detector");
        String monitorId = ((List<String>) (detectorAsMap).get("monitor_id")).get(0);

        String monitorType  = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");

        assertEquals("Monitor type not correct", MonitorType.BUCKET_LEVEL_MONITOR.getValue(), monitorType);

        // Create random doc rule and 5 pre-packed rules and assign to detector
        String randomDocRuleId = createRule(randomRule(), "test_windows");
        List<String> prepackagedRules = getRandomPrePackagedRules();
        input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(randomDocRuleId)),
            prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()), Collections.emptyList());
        Detector updatedDetector = randomDetectorWithInputs(List.of(input));

        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        Map updateResponseBody = asMap(updateResponse);
        detectorId = updateResponseBody.get("_id").toString();

        // Verify newly created doc level monitor
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorAsMap = (Map<String, Object>) hit.getSourceAsMap().get("detector");
        List<String> monitorIds = ((List<String>) (detectorAsMap).get("monitor_id"));

        assertEquals("Number of monitors not correct",1, monitorIds.size());

        monitorId = monitorIds.get(0);
        monitorType  = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");

        assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

        // Verify rules
        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals("Number of rules on query index not correct",6, response.getHits().getTotalHits().value);

        // Verify findings
        indexDoc(index, "1", randomDoc(2, 5, "Info"));
        indexDoc(index, "2", randomDoc(3, 5, "Info"));

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        // 5 prepackaged and 1 custom doc level rule
        assertEquals("Number of doc level sigma rules not correct",6, noOfSigmaRuleMatches);

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        // When doc level monitor is being applied one finding is generated per document
        assertEquals("Number of total findings not correct", 2, getFindingsBody.get("total_findings"));

        Set<String> docRuleIds = new HashSet<>(prepackagedRules);
        docRuleIds.add(randomDocRuleId);

        List<Map<String, Object>> findings = (List)getFindingsBody.get("findings");
        List<String> foundDocIds = new ArrayList<>();
        for(Map<String, Object> finding : findings) {
            Set<String> aggRulesFinding = ((List<Map<String, Object>>)finding.get("queries")).stream().map(it -> it.get("id").toString()).collect(
                Collectors.toSet());

            assertTrue("Finding rules not correct", docRuleIds.containsAll(aggRulesFinding));

            List<String> findingDocs = (List<String>)finding.get("related_doc_ids");
            Assert.assertEquals("Number of documents not correct",1, findingDocs.size());
            foundDocIds.addAll(findingDocs);
        }
        assertTrue("List of documents not correct", Arrays.asList("1", "2").containsAll(foundDocIds));
    }

    /**
     * 1. Creates detector with prepackaged doc rules
     * 2. Verifies that detector with doc level monitor is created
     * 3. Removes all rules and updates detector
     * 4. Verifies that detector doesn't have monitors attached
     *
     * @throws IOException
     */
    public void testRemoveAllRulesAndUpdateDetector_success() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                "  \"partial\":true" +
                "}"
        );
        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        List<String> randomPrepackagedRules = getRandomPrePackagedRules();
        Detector detector = randomDetector(randomPrepackagedRules);
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();
        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals("Number of prepackaged rules not correct", randomPrepackagedRules.size(), response.getHits().getTotalHits().value);

        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";
        // Verify that one doc level monitor is created
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, Object> detectorAsMap = (Map<String, Object>) hit.getSourceAsMap().get("detector");
        List<String> monitorIds = ((List<String>) (detectorAsMap).get("monitor_id"));

        assertEquals("Number of monitors not correct", 1, monitorIds.size());

        String monitorId = monitorIds.get(0);
        String monitorType  = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");

        assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

        Detector updatedDetector = randomDetector(Collections.emptyList());
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorAsMap = (Map<String, Object>) hit.getSourceAsMap().get("detector");

        assertTrue("Monitor list not empty", ((List<String>) (detectorAsMap).get("monitor_id")).isEmpty());
    }

    /**
     * 1. Creates detector with aggregation rule
     * 2. Adds new aggregation rule
     * 3. Updates a detector
     * 4. Verifies that detector has 2 custom rules attached
     * 5. Execute monitors and verifies findings
     *
     * @throws IOException
     */
    public void testAddNewAggregationRule_verifyFindings_success() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        String sumRuleId = createRule(randomAggregationRule("sum", " > 1"), "test_windows");
        List<DetectorRule> detectorRules = List.of(new DetectorRule(sumRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList(), Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();
        String  request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";

        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> detectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = detectorMap.get("inputs");

        assertEquals("Number of custom rules not correct", 1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        // Test adding the new max monitor and updating the existing sum monitor
        String maxRuleId =  createRule(randomAggregationRule("max", " > 3"), "test_windows");
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(maxRuleId), new DetectorRule(sumRuleId)),
            Collections.emptyList(), Collections.emptyList());
        Detector updatedDetector = randomDetectorWithInputs(List.of(newInput));
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        Map<String, List> updatedDetectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        inputArr = updatedDetectorMap.get("inputs");

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        assertEquals(2, monitorIds.size());

        indexDoc(index, "1", randomDoc(2, 4, "Info"));
        indexDoc(index, "2", randomDoc(3, 4, "Info"));

        for(String monitorId: monitorIds) {
            Map<String, String> monitor  = (Map<String, String>)(entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");

            assertEquals("Invalid monitor type", MonitorType.BUCKET_LEVEL_MONITOR.getValue(), monitor.get("monitor_type"));

            executeAlertingMonitor(monitorId, Collections.emptyMap());
        }

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        // Two bucket monitors are executed and only one finding is generated since maxRule is not fulfilling the trigger condition
        assertEquals(1, getFindingsBody.get("total_findings"));

        Map<String, Object> finding = ((List<Map>) getFindingsBody.get("findings")).get(0);

        Set<String> aggRulesFinding = ((List<Map<String, Object>>) finding.get("queries")).stream().map(it -> it.get("id").toString()).collect(
            Collectors.toSet());

        assertEquals(sumRuleId, aggRulesFinding.iterator().next());

        List<String> findingDocs = ((List<String>) finding.get("related_doc_ids"));

        assertEquals("Number of found documents not correct", 2, findingDocs.size());
        assertTrue("Wrong found doc ids", Arrays.asList("1", "2").containsAll(findingDocs));

        String findingDetectorId = ((Map<String, Object>)((List) getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>)((List) getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);
    }

    /**
     * 1. Creates detector with 2 aggregation rule assigned
     * 2. Verifies that 2 custom rules exists
     * 3. Removes one rule and updates a detector
     * 4. Verifies that detector has only one custom rule and one bucket level monitor
     *
     * @throws IOException
     */
    public void testDeleteAggregationRule_verifyFindings_success() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());
        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        List<String> aggRuleIds = new ArrayList<>();
        String avgRuleId = createRule(randomAggregationRule("avg", " > 1"), "test_windows");
        aggRuleIds.add(avgRuleId);
        String countRuleId = createRule(randomAggregationRule("count", " > 1"), "test_windows");
        aggRuleIds.add(countRuleId);

        List<DetectorRule> detectorRules = aggRuleIds.stream().map(DetectorRule::new).collect(Collectors.toList());
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList(), Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();
        String  request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";

        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> detectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = detectorMap.get("inputs");

        assertEquals("Number of custom rules not correct", 2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        // Test deleting the aggregation rule
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(avgRuleId)),
            Collections.emptyList(), Collections.emptyList());
        detector = randomDetectorWithInputs(List.of(newInput));
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        Map<String, List> updatedDetectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        inputArr = updatedDetectorMap.get("inputs");

        assertEquals("Number of custom rules not correct", 1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        // Verify monitors
        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        assertEquals("Number of monitors not correct", 1, monitorIds.size());

        Map<String, String> monitor  = (Map<String, String>)(entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorIds.get(0))))).get("monitor");

        assertEquals("Invalid monitor type", MonitorType.BUCKET_LEVEL_MONITOR.getValue(), monitor.get("monitor_type"));

        indexDoc(index, "1", randomDoc(2, 4, "Info"));
        indexDoc(index, "2", randomDoc(3, 4, "Info"));
        indexDoc(index, "3", randomDoc(3, 4, "Test"));
        executeAlertingMonitor(monitorIds.get(0), Collections.emptyMap());

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);

        assertEquals("Number of total findings not correct", 1, getFindingsBody.get("total_findings"));

        Map<String, Object> finding = ((List<Map>) getFindingsBody.get("findings")).get(0);
        Set<String> aggRulesFinding = ((List<Map<String, Object>>) finding.get("queries")).stream().map(it -> it.get("id").toString()).collect(
            Collectors.toSet());

        assertEquals(avgRuleId, aggRulesFinding.iterator().next());

        List<String> findingDocs = (List<String>) finding.get("related_doc_ids");
        // Matches two findings because of the opCode rule uses (Info)
        assertEquals("Number of found documents not correct", 2, findingDocs.size());
        assertTrue("Wrong found doc ids", Arrays.asList("1", "2").containsAll(findingDocs));

        String findingDetectorId = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);
    }

    /**
     * 1. Creates detector with 2 aggregation and prepackaged doc level rules
     * 2. Replaces one aggregation rule with a new one
     * 3. Verifies that number of rules is unchanged
     * 4. Verifies monitor types
     * 5. Verifies findings
     * @throws IOException
     */
    public void testReplaceAggregationRule_verifyFindings_success() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());
        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        List<String> aggRuleIds = new ArrayList<>();
        String avgRuleId = createRule(randomAggregationRule("avg", " > 1"), "test_windows");
        aggRuleIds.add(avgRuleId);
        String minRuleId = createRule(randomAggregationRule("min", " > 1"), "test_windows");
        aggRuleIds.add(minRuleId);

        List<DetectorRule> detectorRules = aggRuleIds.stream().map(DetectorRule::new).collect(Collectors.toList());
        List<String> prepackagedDocRules = getRandomPrePackagedRules();

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            prepackagedDocRules.stream().map(DetectorRule::new).collect(Collectors.toList()), Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();
        String  request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";

        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> detectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = detectorMap.get("inputs");

        assertEquals("Number of custom rules not correct", 2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        String maxRuleId = createRule(randomAggregationRule("max", " > 2"), "test_windows");
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"),
            List.of(new DetectorRule(avgRuleId), new DetectorRule(maxRuleId)),
            getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()), Collections.emptyList());
        detector = randomDetectorWithInputs(List.of(newInput));
        createResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(createResponse));

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        Map<String, List> updatedDetectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        inputArr = updatedDetectorMap.get("inputs");

        assertEquals("Number of custom rules not correct", 2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        assertEquals("Number of monitors not correct", 3, monitorIds.size());

        indexDoc(index, "1", randomDoc(2, 4, "Info"));
        indexDoc(index, "2", randomDoc(3, 4, "Info"));
        indexDoc(index, "3", randomDoc(3, 4, "Test"));
        Map<String, Integer> numberOfMonitorTypes = new HashMap<>();
        for(String monitorId: monitorIds) {
            Map<String, String> monitor  = (Map<String, String>)(entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
            numberOfMonitorTypes.merge(monitor.get("monitor_type"), 1, Integer::sum);
            executeAlertingMonitor(monitorId, Collections.emptyMap());
        }

        assertEquals("Number of bucket level monitors not correct", 2, numberOfMonitorTypes.get(MonitorType.BUCKET_LEVEL_MONITOR.getValue()).intValue());
        assertEquals("Number of doc level monitors not correct", 1, numberOfMonitorTypes.get(MonitorType.DOC_LEVEL_MONITOR.getValue()).intValue());
        // Verify findings
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        assertEquals("Number of total findings not correct", 5, getFindingsBody.get("total_findings"));

        String findingDetectorId = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);

        List<String> docLevelFinding = new ArrayList<>();
        List<Map<String, Object>> findings = (List)getFindingsBody.get("findings");

        Set<String> docLevelRules = new HashSet<>(prepackagedDocRules);

        for(Map<String, Object> finding : findings) {
            List<Map<String, Object>> queries = (List<Map<String, Object>>)finding.get("queries");
            Set<String> findingRules = queries.stream().map(it -> it.get("id").toString()).collect(Collectors.toSet());
            // In this test case all doc level rules are matching the finding rule ids
            if (docLevelRules.containsAll(findingRules)) {
                docLevelFinding.addAll((List<String>)finding.get("related_doc_ids"));
            } else {
                List<String> findingDocs = (List<String>)finding.get("related_doc_ids");

                assertEquals("Number of found documents not correct", 2, findingDocs.size());
                assertTrue("Wrong found doc ids", Arrays.asList("1", "2").containsAll(findingDocs));
            }
        }
        // Verify doc level finding
        assertTrue("Wrong found doc ids", Arrays.asList("1", "2", "3").containsAll(docLevelFinding));
    }

    public void testMinAggregationRule_findingSuccess() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());
        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        List<String> aggRuleIds = new ArrayList<>();
        String testOpCode = "Test";
        aggRuleIds.add(createRule(randomAggregationRule("min", " > 3", testOpCode), "test_windows"));
        List<DetectorRule> detectorRules = aggRuleIds.stream().map(DetectorRule::new).collect(Collectors.toList());
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList(), Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();
        String  request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";

        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> detectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));

        indexDoc(index, "4", randomDoc(5, 3, testOpCode));
        indexDoc(index, "5", randomDoc(2, 3, testOpCode));
        indexDoc(index, "6", randomDoc(4, 3, testOpCode));
        indexDoc(index, "7", randomDoc(6, 2, testOpCode));
        indexDoc(index, "8", randomDoc(1, 1, testOpCode));

        Map<String, Integer> numberOfMonitorTypes = new HashMap<>();
        for (String monitorId: monitorIds) {
            Map<String, String> monitor  = (Map<String, String>)(entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
            numberOfMonitorTypes.merge(monitor.get("monitor_type"), 1, Integer::sum);
            executeAlertingMonitor(monitorId, Collections.emptyMap());
        }

        // Verify findings
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);

        List<Map<String, Object>> findings = (List)getFindingsBody.get("findings");
        for (Map<String, Object> finding : findings) {
            List<String> findingDocs = (List<String>)finding.get("related_doc_ids");

            assertEquals("Number of found documents not correct", 1, findingDocs.size());
            assertTrue("Wrong found doc ids", Arrays.asList("7").containsAll(findingDocs));
        }

        String findingDetectorId = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);
    }


    /**
     * 1. Creates detector with aggregation and prepackaged rules
     * (sum rule - should match docIds: 1, 2, 3; maxRule - 4, 5, 6, 7; minRule - 7)
     * 2. Verifies monitor execution
     * 3. Verifies findings
     *
     * @throws IOException
     */
    public void testMultipleAggregationAndDocRules_findingSuccess() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        String infoOpCode = "Info";
        String testOpCode = "Test";

        // 5 custom aggregation rules
        String sumRuleId = createRule(randomAggregationRule("sum", " > 1", infoOpCode), "test_windows");
        String maxRuleId =  createRule(randomAggregationRule("max", " > 3", testOpCode), "test_windows");
        String minRuleId =  createRule(randomAggregationRule("min", " > 3", testOpCode), "test_windows");
        String avgRuleId =  createRule(randomAggregationRule("avg", " > 3", infoOpCode), "test_windows");
        String cntRuleId =  createRule(randomAggregationRule("count", " > 3", "randomTestCode"), "test_windows");
        List<String> aggRuleIds = List.of(sumRuleId, maxRuleId);
        // 1 custom doc level rule
        String randomDocRuleId = createRule(randomRule(), "test_windows");
        // 5 prepackaged rules
        List<String> prepackagedRules = getRandomPrePackagedRules();

        List<DetectorRule> detectorRules = List.of(new DetectorRule(sumRuleId), new DetectorRule(maxRuleId), new DetectorRule(minRuleId),
            new DetectorRule(avgRuleId), new DetectorRule(cntRuleId), new DetectorRule(randomDocRuleId));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()), Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals("Number of doc level rules not correct", 6, response.getHits().getTotalHits().value);

        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();
        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> updatedDetectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = updatedDetectorMap.get("inputs");

        assertEquals("Number of custom rules not correct", 6, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        assertEquals("Number of monitors not correct", 6, monitorIds.size());

        indexDoc(index, "1", randomDoc(2, 4, infoOpCode));
        indexDoc(index, "2", randomDoc(3, 4, infoOpCode));
        indexDoc(index, "3", randomDoc(1, 4, infoOpCode));
        indexDoc(index, "4", randomDoc(5, 3, testOpCode));
        indexDoc(index, "5", randomDoc(2, 3, testOpCode));
        indexDoc(index, "6", randomDoc(4, 3, testOpCode));
        indexDoc(index, "7", randomDoc(6, 2, testOpCode));
        indexDoc(index, "8", randomDoc(1, 1, testOpCode));

        Map<String, Integer> numberOfMonitorTypes = new HashMap<>();

        for (String monitorId: monitorIds) {
            Map<String, String> monitor  = (Map<String, String>)(entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
            numberOfMonitorTypes.merge(monitor.get("monitor_type"), 1, Integer::sum);
            Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());

            // Assert monitor executions
            Map<String, Object> executeResults = entityAsMap(executeResponse);
            if (MonitorType.DOC_LEVEL_MONITOR.getValue().equals(monitor.get("monitor_type"))) {
                int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
                // 5 prepackaged and 1 custom doc level rule
                assertEquals("Number of sigma rules not correct", 6, noOfSigmaRuleMatches);
            } else {
                for(String ruleId: aggRuleIds) {
                    Object rule = (((Map<String,Object>)((Map<String, Object>)((List<Object>)((Map<String, Object>)executeResults.get("input_results")).get("results")).get(0)).get("aggregations")).get(ruleId));
                    if (rule != null) {
                        if (ruleId.equals(sumRuleId)) {
                            assertRuleMonitorFinding(executeResults, ruleId,3, List.of("4"));
                        } else if (ruleId.equals(maxRuleId)) {
                            assertRuleMonitorFinding(executeResults, ruleId,5, List.of("2", "3"));
                        }
                        else if (ruleId.equals(minRuleId)) {
                            assertRuleMonitorFinding(executeResults, ruleId,1,  List.of("2"));
                        }
                    }
                }
            }
        }

        assertEquals("Number of bucket level monitors not correct", 5, numberOfMonitorTypes.get(MonitorType.BUCKET_LEVEL_MONITOR.getValue()).intValue());
        assertEquals("Number of doc level monitors not correct", 1, numberOfMonitorTypes.get(MonitorType.DOC_LEVEL_MONITOR.getValue()).intValue());

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        // Assert findings
        assertNotNull(getFindingsBody);
        // 8 findings from doc level rules, and 3 findings for aggregation (sum, max and min)
        assertEquals("Number of total findings not correct", 11, getFindingsBody.get("total_findings"));

        String findingDetectorId = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);

        List<String> docLevelFinding = new ArrayList<>();
        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");

        Set<String> docLevelRules = new HashSet<>(prepackagedRules);
        docLevelRules.add(randomDocRuleId);

        for(Map<String, Object> finding : findings) {
            List<Map<String, Object>> queries = (List<Map<String, Object>>)finding.get("queries");
            Set<String> findingRuleIds = queries.stream().map(it -> it.get("id").toString()).collect(Collectors.toSet());
            // Doc level finding matches all doc level rules (including the custom one) in this test case
            if (docLevelRules.containsAll(findingRuleIds)) {
                docLevelFinding.addAll((List<String>)finding.get("related_doc_ids"));
            } else {
                // In the case of bucket level monitors, queries will always contain one value
                String aggRuleId = findingRuleIds.iterator().next();
                List<String> findingDocs = (List<String>)finding.get("related_doc_ids");

                if (aggRuleId.equals(sumRuleId)) {
                    assertTrue("Wrong found doc ids for sum rule", List.of("1", "2", "3").containsAll(findingDocs));
                } else if (aggRuleId.equals(maxRuleId)) {
                    assertTrue("Wrong found doc ids for max rule", List.of("4", "5", "6", "7").containsAll(findingDocs));
                } else if (aggRuleId.equals(minRuleId)) {
                    assertTrue("Wrong found doc ids for min rule", List.of("7").containsAll(findingDocs));
                }
            }
        }

        assertTrue(Arrays.asList("Wrong found doc ids", "1", "2", "3", "4", "5", "6", "7", "8").containsAll(docLevelFinding));
    }

    /**
     * 1. Creates detector with aggregation and prepackaged rules;
     * aggregation rules - windows category; custom doc level rule - windows category; prepackaged rules - test_windows category
     * 2. Verifies monitor execution
     * 3. Verifies findings by getting the findings by detector id (join findings for all rule categories/ log types)
     * @throws IOException
     */
    public void testMultipleAggregationAndDocRulesForMultipleDetectorTypes_findingSuccess() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        String lin = "s3";

        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + lin + "\", " +
                "  \"partial\":true" +
                "}"
        );

        createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        String infoOpCode = "Info";
        String testOpCode = "Test";

        // 5 custom aggregation rules
        String sumRuleId = createRule(randomAggregationRule("sum", " > 1", infoOpCode));
        String maxRuleId =  createRule(randomAggregationRule("max", " > 3", testOpCode));
        String minRuleId =  createRule(randomAggregationRule("min", " > 3", testOpCode));
        String avgRuleId =  createRule(randomAggregationRule("avg", " > 3", infoOpCode));
        String cntRuleId =  createRule(randomAggregationRule("count", " > 3", "randomTestCode"));
        List<String> aggRuleIds = List.of(sumRuleId, maxRuleId);
        String randomDocRuleId = createRule(randomRule());
        List<String> prepackagedRules = getRandomPrePackagedRules();

        List<DetectorRule> detectorRules = List.of(new DetectorRule(sumRuleId), new DetectorRule(maxRuleId), new DetectorRule(minRuleId),
            new DetectorRule(avgRuleId), new DetectorRule(cntRuleId), new DetectorRule(randomDocRuleId));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()), List.of(DetectorType.TEST_WINDOWS, DetectorType.WINDOWS));
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex("test_windows"), request, true);
        assertEquals("Number of doc level rules not correct for test_windows rule category", 5, response.getHits().getTotalHits().value);

        response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex("windows"), request, true);
        assertEquals("Number of doc level rules not correct for windows rule category", 1, response.getHits().getTotalHits().value);


        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();
        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> updatedDetectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = updatedDetectorMap.get("inputs");

        assertEquals("Number of custom rules not correct", 6, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        assertEquals(7, monitorIds.size());

        indexDoc(index, "1", randomDoc(2, 4, infoOpCode));
        indexDoc(index, "2", randomDoc(3, 4, infoOpCode));
        indexDoc(index, "3", randomDoc(1, 4, infoOpCode));
        indexDoc(index, "4", randomDoc(5, 3, testOpCode));
        indexDoc(index, "5", randomDoc(2, 3, testOpCode));
        indexDoc(index, "6", randomDoc(4, 3, testOpCode));
        indexDoc(index, "7", randomDoc(6, 2, testOpCode));
        indexDoc(index, "8", randomDoc(1, 1, testOpCode));

        Map<String, Integer> numberOfMonitorTypes = new HashMap<>();

        String windowsMonitorId = (String)((Map<String, Object>)updatedDetectorMap.get("doc_monitor_id_per_category")).get("windows");
        String testWindowsMonitorId = (String)((Map<String, Object>)updatedDetectorMap.get("doc_monitor_id_per_category")).get("test_windows");
        for (String monitorId: monitorIds) {
            Map<String, String> monitor  = (Map<String, String>)(entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
            numberOfMonitorTypes.merge(monitor.get("monitor_type"), 1, Integer::sum);
            Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());

            // Assert monitor executions
            Map<String, Object> executeResults = entityAsMap(executeResponse);
            if (MonitorType.DOC_LEVEL_MONITOR.getValue().equals(monitor.get("monitor_type"))) {
                int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
                // 5 prepackaged and 1 custom doc level rule
                if (monitorId.equals(windowsMonitorId)) {
                    assertEquals("Number of doc level rules in monitor executions for windows monitor not correct", 1, noOfSigmaRuleMatches);
                }
                if (monitorId.equals(testWindowsMonitorId)) {
                    assertEquals("Number of doc level rules in monitor executions for test_windows monitor not correct", 5, noOfSigmaRuleMatches);
                }

            } else {
                for(String ruleId: aggRuleIds) {
                    Object rule = (((Map<String,Object>)((Map<String, Object>)((List<Object>)((Map<String, Object>)executeResults.get("input_results")).get("results")).get(0)).get("aggregations")).get(ruleId));
                    if (rule != null) {
                        if (ruleId == sumRuleId) {
                            assertRuleMonitorFinding(executeResults, ruleId,3, List.of("4"));
                        } else if (ruleId == maxRuleId) {
                            assertRuleMonitorFinding(executeResults, ruleId,5, List.of("2", "3"));
                        }
                        else if (ruleId == minRuleId) {
                            assertRuleMonitorFinding(executeResults, ruleId,1,  List.of("2"));
                        }
                    }
                }
            }
        }

        assertEquals("Number of bucket level monitors not correct", 5, numberOfMonitorTypes.get(MonitorType.BUCKET_LEVEL_MONITOR.getValue()).intValue());
        assertEquals("Number of doc level monitors not correct", 2, numberOfMonitorTypes.get(MonitorType.DOC_LEVEL_MONITOR.getValue()).intValue());

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        // Assert findings
        assertNotNull(getFindingsBody);
        // 8 findings for 5 prepackaged doc level rules for test_windows category
        // 8 findings for 1 custom doc level rule for windows category
        // 3 findings for bucket level monitors for windows
        assertEquals("Number of total findings not correct",19, getFindingsBody.get("total_findings"));

        String findingDetectorId = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);

        List<String> docLevelFinding = new ArrayList<>();
        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");

        Set<String> docLevelRules = new HashSet<>(prepackagedRules);
        docLevelRules.add(randomDocRuleId);

        for(Map<String, Object> finding : findings) {
            List<Map<String, Object>> queries = (List<Map<String, Object>>)finding.get("queries");
            Set<String> findingRuleIds = queries.stream().map(it -> it.get("id").toString()).collect(Collectors.toSet());
            // Doc level finding matches all doc level rules (including the custom one) in this test case
            if (docLevelRules.containsAll(findingRuleIds)) {
                docLevelFinding.addAll((List<String>)finding.get("related_doc_ids"));
            } else {
                // In the case of bucket level monitors, queries will always contain one value
                String aggRuleId = findingRuleIds.iterator().next();
                List<String> findingDocs = (List<String>)finding.get("related_doc_ids");

                if (aggRuleId.equals(sumRuleId)) {
                    assertTrue("Wrong found doc ids for sum rule", List.of("1", "2", "3").containsAll(findingDocs));
                } else if (aggRuleId.equals(maxRuleId)) {
                    assertTrue("Wrong found doc ids for max rule", List.of("4", "5", "6", "7").containsAll(findingDocs));
                } else if (aggRuleId.equals( minRuleId)) {
                    assertTrue("Wrong found doc ids for min rule", List.of("7").containsAll(findingDocs));
                }
            }
        }

        assertTrue("Wrong found doc ids", Arrays.asList("1", "2", "3", "4", "5", "6", "7", "8").containsAll(docLevelFinding));
    }

    /**
     * 1. Create aggregation rules - windows category; pre-packaged rules - test_windows category; random doc rule - windows category
     * 2. Verifies monitor number and rule types and their numbers
     * 3. Updates the detector by removing the custom doc level rule and all prepackaged rules
     * 4. Verifies that two query indices are removed
     * 5. Verifies removed monitors
     * @throws IOException
     */
    public void testRemoveDocLevelRulesAndOneDetectorType_findingSuccess() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        String infoOpCode = "Info";
        String testOpCode = "Test";

        // 5 custom aggregation rules
        String sumRuleId = createRule(randomAggregationRule("sum", " > 1", infoOpCode));
        String maxRuleId =  createRule(randomAggregationRule("max", " > 3", testOpCode));
        String minRuleId =  createRule(randomAggregationRule("min", " > 3", testOpCode));
        String avgRuleId =  createRule(randomAggregationRule("avg", " > 3", infoOpCode));
        String cntRuleId =  createRule(randomAggregationRule("count", " > 3", "randomTestCode"));
        String randomDocRuleId = createRule(randomRule());
        List<String> prepackagedRules = getRandomPrePackagedRules();

        List<DetectorRule> detectorRules = List.of(new DetectorRule(sumRuleId), new DetectorRule(maxRuleId), new DetectorRule(minRuleId),
            new DetectorRule(avgRuleId), new DetectorRule(cntRuleId), new DetectorRule(randomDocRuleId));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()), List.of(DetectorType.TEST_WINDOWS, DetectorType.WINDOWS));
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex("test_windows"), request, true);
        assertEquals("Number of doc level rules for test_windows category not correct", 5, response.getHits().getTotalHits().value);

        response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex("windows"), request, true);
        assertEquals("Number of doc level rules for windows category not correct", 1, response.getHits().getTotalHits().value);

        response = executeSearchAndGetResponse(Rule.CUSTOM_RULES_INDEX, request, true);
        assertEquals("Number of custom rules not correct", 6, response.getHits().getTotalHits().value);


        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();
        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> detectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = detectorMap.get("inputs");

        assertEquals("Number of custom rules not correct", 6, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));

        assertEquals("Number of monitors not correct", 7, monitorIds.size());
        Map<String, String> docLevelMonitorIdPerCategory = ((Map<String, String>)((Map<String, Object>)hit.getSourceAsMap().get("detector")).get("doc_monitor_id_per_category"));
        Collection<String> docLevelMonitorIds = docLevelMonitorIdPerCategory.values();
        // verify that detector list of doc monitor ids is correct
        assertTrue("Monitor list doesn't contain doc level monitor ids", monitorIds.containsAll(docLevelMonitorIds));
        // Updating detector - removing prepackaged and custom doc level rules for test_windows category; Removing the detector type
        detectorRules = List.of(new DetectorRule(sumRuleId), new DetectorRule(maxRuleId), new DetectorRule(minRuleId), new DetectorRule(avgRuleId), new DetectorRule(cntRuleId));
        input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules, Collections.emptyList(), List.of(DetectorType.WINDOWS));
        /**
        Detector updatedDetector = randomDetectorWithInputs(List.of(input));
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));
        // Query index for test_windows and windows removed since all doc level monitors related to these indices are removed
        assertFalse("test_windows query index exists", doesIndexExist(DetectorMonitorConfig.getRuleIndex(DetectorType.TEST_WINDOWS.getDetectorType())));
        assertFalse("windows query index exists", doesIndexExist(DetectorMonitorConfig.getRuleIndex(DetectorType.WINDOWS.getDetectorType())));

        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        // Custom created doc rule removed from detector
        response = executeSearchAndGetResponse(Rule.CUSTOM_RULES_INDEX, request, true);
        assertEquals("Number of custom rules not correct after removal of query index", 6, response.getHits().getTotalHits().value);

        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        // Verify that two doc level monitors are removed - one for windows (removed custom doc level rule) and the second for test_windows category
        assertEquals("Number of monitors not correct after doc level monitors removed", 5, monitorIds.size());
        assertTrue("Removed doc level monitors still exists in monitor list", !monitorIds.containsAll(docLevelMonitorIds));**/
    }

    /**
     * 1. Create pre-packaged rules - test_windows category; random doc rule - windows category and one aggregation rule
     * 2. Verifies monitor number and rule types and their numbers
     * 3. Updates the detector by removing the custom doc level rule and all prepackaged rules
     * 4. Verifies that two query indices are removed
     * 5. Verifies removed monitors
     * @throws IOException
     */
    public void testRemoveBucketLevelRuleAndOneDetectorType_findingSuccess() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        String testOpCode = "Test";

        // 1 custom aggregation rules
        String maxRuleId =  createRule(randomAggregationRule("max", " > 3", testOpCode));

        String customDocRuleId = createRule(randomRule(), "test_windows");
        List<String> prepackagedRules = getRandomPrePackagedRules();

        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId), new DetectorRule(customDocRuleId));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()), List.of(DetectorType.TEST_WINDOWS, DetectorType.WINDOWS));
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex("test_windows"), request, true);
        assertEquals("Number of doc level rules not correct",6, response.getHits().getTotalHits().value);

        response = executeSearchAndGetResponse(Rule.CUSTOM_RULES_INDEX, request, true);
        assertEquals("Number of custom rules not correct", 2, response.getHits().getTotalHits().value);

        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();
        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> detectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = detectorMap.get("inputs");

        assertEquals("Number of custom rules not correct", 2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));

        assertEquals("Number of monitors not correct", 2, monitorIds.size());

        // verify that detector list of doc monitor ids is correct
        Map<String, String> docLevelMonitorIdPerCategory = ((Map<String, String>)((Map<String, Object>)hit.getSourceAsMap().get("detector")).get("doc_monitor_id_per_category"));
        Collection<String> docLevelMonitorIds = docLevelMonitorIdPerCategory.values();
        assertTrue(monitorIds.containsAll(docLevelMonitorIds));

        // verify that detector list of bucket monitor ids is correct
        Map<String, String> bucketLevelMonitorIdPerRule = ((Map<String, String>)((Map<String, Object>)hit.getSourceAsMap().get("detector")).get("bucket_monitor_id_rule_id"));
        Collection<String> bucketLevelMonitorIds = bucketLevelMonitorIdPerRule.values();

        assertTrue("Monitor list doesn't contain all bucket level monitors", monitorIds.containsAll(bucketLevelMonitorIds));

        // Updating detector - removing prepackaged and custom doc level rules for test_windows category; Removing the detector type
        detectorRules = List.of(new DetectorRule(customDocRuleId));
        input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules, Collections.emptyList(), List.of(DetectorType.WINDOWS));
        Detector updatedDetector = randomDetectorWithInputs(List.of(input));
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));
        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        assertTrue("test_windows query index doesn't exist", doesIndexExist(DetectorMonitorConfig.getRuleIndex(DetectorType.TEST_WINDOWS.getDetectorType())));
        assertTrue("windows query index doesn't exist", doesIndexExist(DetectorMonitorConfig.getRuleIndex(DetectorType.WINDOWS.getDetectorType())));

        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        // Custom created doc rule removed from detector
        response = executeSearchAndGetResponse(Rule.CUSTOM_RULES_INDEX, request, true);
        assertEquals("Number of custom rules not correct after ", 2, response.getHits().getTotalHits().value);

        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        monitorIds = ((List<String>) (detectorMap).get("monitor_id"));

        assertEquals("Number of monitors not correct after monitor removal of bucket level monitor", 1, monitorIds.size());
        assertTrue(!monitorIds.containsAll(bucketLevelMonitorIds));
    }

    private static void assertRuleMonitorFinding(Map<String, Object> executeResults, String ruleId,  int expectedDocCount, List<String> expectedTriggerResult) {
        List<Map<String, Object>> buckets = ((List<Map<String, Object>>)(((Map<String, Object>)((Map<String, Object>)((Map<String, Object>)((List<Object>)((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0)).get("aggregations")).get("result_agg")).get("buckets")));
        Integer docCount = buckets.stream().mapToInt(it -> (Integer)it.get("doc_count")).sum();
        assertEquals("Total doc count not correct", expectedDocCount, docCount.intValue());

        List<String> triggerResultBucketKeys = ((Map<String, Object>)((Map<String, Object>) ((Map<String, Object>)executeResults.get("trigger_results")).get(ruleId)).get("agg_result_buckets")).keySet().stream().collect(Collectors.toList());
        assertEquals("Trigger result not correct", expectedTriggerResult, triggerResultBucketKeys);
    }
}
