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
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.hc.core5.http.HttpStatus;
import org.junit.Assert;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.commons.alerting.model.Monitor.MonitorType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
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

        assertEquals(5, response.getHits().getTotalHits().value);

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

        assertEquals(1, monitorIds.size());

        String monitorId = monitorIds.get(0);
        String monitorType  = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");

        assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

        // Create aggregation rules
        String sumRuleId = createRule(randomAggregationRule( "sum", " > 2"));
        String avgTermRuleId = createRule(randomAggregationRule( "avg", " > 1"));
        // Update detector and empty doc level rules so detector contains only one aggregation rule
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(sumRuleId), new DetectorRule(avgTermRuleId)),
            Collections.emptyList());
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
            Assert.assertEquals(MonitorType.BUCKET_LEVEL_MONITOR.getValue(), monitorType);
            executeAlertingMonitor(id, Collections.emptyMap());
        }
        // verify bucket level monitor findings
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        assertEquals(2, getFindingsBody.get("total_findings"));

        List<String> aggRuleIds = List.of(sumRuleId, avgTermRuleId);

        List<Map<String, Object>> findings = (List)getFindingsBody.get("findings");
        for(Map<String, Object> finding : findings) {
            Set<String> aggRulesFinding = ((List<Map<String, Object>>)finding.get("queries")).stream().map(it -> it.get("id").toString()).collect(
                Collectors.toSet());
            // Bucket monitor finding will have one rule
            String aggRuleId = aggRulesFinding.iterator().next();

            assertTrue(aggRulesFinding.contains(aggRuleId));

            List<String> findingDocs = (List<String>)finding.get("related_doc_ids");
            Assert.assertEquals(2, findingDocs.size());
            assertTrue(Arrays.asList("1", "2").containsAll(findingDocs));
        }

        String findingDetectorId = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

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

        String maxRuleId = createRule(randomAggregationRule( "max", " > 2"));
        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList());
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

        assertEquals(1, response.getHits().getTotalHits().value);

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

        assertEquals(MonitorType.BUCKET_LEVEL_MONITOR.getValue(), monitorType);

        // Create random doc rule and 5 pre-packed rules and assign to detector
        String randomDocRuleId = createRule(randomRule());
        List<String> prepackagedRules = getRandomPrePackagedRules();
        input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(randomDocRuleId)),
            prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()));
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

        assertEquals(1, monitorIds.size());

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

        assertEquals(6, response.getHits().getTotalHits().value);

        // Verify findings
        indexDoc(index, "1", randomDoc(2, 5, "Info"));
        indexDoc(index, "2", randomDoc(3, 5, "Info"));

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        // 5 prepackaged and 1 custom doc level rule
        assertEquals(6, noOfSigmaRuleMatches);

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        // When doc level monitor is being applied one finding is generated per document
        assertEquals(2, getFindingsBody.get("total_findings"));

        Set<String> docRuleIds = new HashSet<>(prepackagedRules);
        docRuleIds.add(randomDocRuleId);

        List<Map<String, Object>> findings = (List)getFindingsBody.get("findings");
        List<String> foundDocIds = new ArrayList<>();
        for(Map<String, Object> finding : findings) {
            Set<String> aggRulesFinding = ((List<Map<String, Object>>)finding.get("queries")).stream().map(it -> it.get("id").toString()).collect(
                Collectors.toSet());

            assertTrue(docRuleIds.containsAll(aggRulesFinding));

            List<String> findingDocs = (List<String>)finding.get("related_doc_ids");
            Assert.assertEquals(1, findingDocs.size());
            foundDocIds.addAll(findingDocs);
        }
        assertTrue(Arrays.asList("1", "2").containsAll(foundDocIds));
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

        assertEquals(randomPrepackagedRules.size(), response.getHits().getTotalHits().value);

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

        assertEquals(1, monitorIds.size());

        String monitorId = monitorIds.get(0);
        String monitorType  = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");

        assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

        Detector updatedDetector = randomDetector(Collections.emptyList());
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        Map<String, Object> updateResponseBody = asMap(updateResponse);
        detectorId = updateResponseBody.get("_id").toString();

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorAsMap = (Map<String, Object>) hit.getSourceAsMap().get("detector");

        assertTrue(((List<String>) (detectorAsMap).get("monitor_id")).isEmpty());
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

        String sumRuleId = createRule(randomAggregationRule("sum", " > 1"));
        List<DetectorRule> detectorRules = List.of(new DetectorRule(sumRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList());
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

        assertEquals(1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        // Test adding the new max monitor and updating the existing sum monitor
        String maxRuleId =  createRule(randomAggregationRule("max", " > 3"));
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(maxRuleId), new DetectorRule(sumRuleId)),
            Collections.emptyList());
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
            assertEquals(MonitorType.BUCKET_LEVEL_MONITOR.getValue(), monitor.get("monitor_type"));
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

        assertEquals(2, findingDocs.size());
        assertTrue(Arrays.asList("1", "2").containsAll(findingDocs));

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
        String avgRuleId = createRule(randomAggregationRule("avg", " > 1"));
        aggRuleIds.add(avgRuleId);
        String countRuleId = createRule(randomAggregationRule("count", " > 1"));
        aggRuleIds.add(countRuleId);

        List<DetectorRule> detectorRules = aggRuleIds.stream().map(DetectorRule::new).collect(Collectors.toList());
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList());
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

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        // Test deleting the aggregation rule
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(avgRuleId)),
            Collections.emptyList());
        detector = randomDetectorWithInputs(List.of(newInput));
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        Map<String, List> updatedDetectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        inputArr = updatedDetectorMap.get("inputs");

        assertEquals(1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        inputArr = updatedDetectorMap.get("inputs");

        assertEquals(1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        // Verify monitors
        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        assertEquals(1, monitorIds.size());

        Map<String, String> monitor  = (Map<String, String>)(entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorIds.get(0))))).get("monitor");

        assertEquals(MonitorType.BUCKET_LEVEL_MONITOR.getValue(), monitor.get("monitor_type"));

        indexDoc(index, "1", randomDoc(2, 4, "Info"));
        indexDoc(index, "2", randomDoc(3, 4, "Info"));
        indexDoc(index, "3", randomDoc(3, 4, "Test"));
        executeAlertingMonitor(monitorIds.get(0), Collections.emptyMap());

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);

        assertEquals(1, getFindingsBody.get("total_findings"));

        Map<String, Object> finding = ((List<Map>) getFindingsBody.get("findings")).get(0);
        Set<String> aggRulesFinding = ((List<Map<String, Object>>) finding.get("queries")).stream().map(it -> it.get("id").toString()).collect(
            Collectors.toSet());

        assertEquals(avgRuleId, aggRulesFinding.iterator().next());

        List<String> findingDocs = (List<String>) finding.get("related_doc_ids");
        // Matches two findings because of the opCode rule uses (Info)
        assertEquals(2, findingDocs.size());
        assertTrue(Arrays.asList("1", "2").containsAll(findingDocs));

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
        String avgRuleId = createRule(randomAggregationRule("avg", " > 1"));
        aggRuleIds.add(avgRuleId);
        String minRuleId = createRule(randomAggregationRule("min", " > 1"));
        aggRuleIds.add(minRuleId);

        List<DetectorRule> detectorRules = aggRuleIds.stream().map(DetectorRule::new).collect(Collectors.toList());
        List<String> prepackagedDocRules = getRandomPrePackagedRules();

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            prepackagedDocRules.stream().map(DetectorRule::new).collect(Collectors.toList()));
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

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        String maxRuleId = createRule(randomAggregationRule("max", " > 2"));
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"),
            List.of(new DetectorRule(avgRuleId), new DetectorRule(maxRuleId)),
            getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        detector = randomDetectorWithInputs(List.of(newInput));
        createResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(createResponse));

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        Map<String, List> updatedDetectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        inputArr = updatedDetectorMap.get("inputs");

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        assertEquals(3, monitorIds.size());

        indexDoc(index, "1", randomDoc(2, 4, "Info"));
        indexDoc(index, "2", randomDoc(3, 4, "Info"));
        indexDoc(index, "3", randomDoc(3, 4, "Test"));
        Map<String, Integer> numberOfMonitorTypes = new HashMap<>();
        for(String monitorId: monitorIds) {
            Map<String, String> monitor  = (Map<String, String>)(entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
            numberOfMonitorTypes.merge(monitor.get("monitor_type"), 1, Integer::sum);
            executeAlertingMonitor(monitorId, Collections.emptyMap());
        }

        assertEquals(2, numberOfMonitorTypes.get(MonitorType.BUCKET_LEVEL_MONITOR.getValue()).intValue());
        assertEquals(1, numberOfMonitorTypes.get(MonitorType.DOC_LEVEL_MONITOR.getValue()).intValue());
        // Verify findings
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        assertEquals(5, getFindingsBody.get("total_findings"));

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
            if(docLevelRules.containsAll(findingRules)) {
                docLevelFinding.addAll((List<String>)finding.get("related_doc_ids"));
            } else {
                String aggRuleId = findingRules.iterator().next();

                List<String> findingDocs = (List<String>)finding.get("related_doc_ids");
                Assert.assertEquals(2, findingDocs.size());
                assertTrue(Arrays.asList("1", "2").containsAll(findingDocs));
            }
        }
        // Verify doc level finding
        assertTrue(Arrays.asList("1", "2", "3").containsAll(docLevelFinding));
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
        aggRuleIds.add(createRule(randomAggregationRule("min", " > 3", testOpCode)));
        List<DetectorRule> detectorRules = aggRuleIds.stream().map(id -> new DetectorRule(id)).collect(Collectors.toList());
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList());
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
            Assert.assertEquals(1, findingDocs.size());
            assertTrue(Arrays.asList("7").containsAll(findingDocs));
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
            prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));



        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals(6, response.getHits().getTotalHits().value);

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));
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

        assertEquals(6, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        assertEquals(6, monitorIds.size());

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
                assertEquals(6, noOfSigmaRuleMatches);
            } else {
                for(String ruleId: aggRuleIds) {
                    Object rule = (((Map<String,Object>)((Map<String, Object>)((List<Object>)((Map<String, Object>)executeResults.get("input_results")).get("results")).get(0)).get("aggregations")).get(ruleId));
                    if(rule != null) {
                        if(ruleId == sumRuleId) {
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

        assertEquals(5, numberOfMonitorTypes.get(MonitorType.BUCKET_LEVEL_MONITOR.getValue()).intValue());
        assertEquals(1, numberOfMonitorTypes.get(MonitorType.DOC_LEVEL_MONITOR.getValue()).intValue());

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        // Assert findings
        assertNotNull(getFindingsBody);
        // 8 findings from doc level rules, and 3 findings for aggregation (sum, max and min)
        assertEquals(11, getFindingsBody.get("total_findings"));

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
            if(docLevelRules.containsAll(findingRuleIds)) {
                docLevelFinding.addAll((List<String>)finding.get("related_doc_ids"));
            } else {
                // In the case of bucket level monitors, queries will always contain one value
                String aggRuleId = findingRuleIds.iterator().next();
                List<String> findingDocs = (List<String>)finding.get("related_doc_ids");

                if(aggRuleId.equals(sumRuleId)) {
                    assertTrue(List.of("1", "2", "3").containsAll(findingDocs));
                } else if(aggRuleId.equals(maxRuleId)) {
                    assertTrue(List.of("4", "5", "6", "7").containsAll(findingDocs));
                } else if(aggRuleId.equals( minRuleId)) {
                    assertTrue(List.of("7").containsAll(findingDocs));
                }
            }
        }

        assertTrue(Arrays.asList("1", "2", "3", "4", "5", "6", "7", "8").containsAll(docLevelFinding));
    }

    public void testCreateDetector_verifyWorkflowCreation_success() throws IOException {
        updateClusterSetting(ENABLE_WORKFLOW_USAGE.getKey(), "true");
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

        String maxRuleId =  createRule(randomAggregationRule("max", " > 3", testOpCode));
        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId), new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

         assertEquals(2, response.getHits().getTotalHits().value);

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));
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
        Map<String, Object> detectorMap = (HashMap<String, Object>)(hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(3, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 3);
    }

    public void testUpdateDetector_disabledWorkflowUsage_verifyWorkflowNotCreated_success() throws IOException {
        // By default, workflow usage is disabled - disabling it just in any case
        updateClusterSetting(ENABLE_WORKFLOW_USAGE.getKey(), "false");
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

        String randomDocRuleId = createRule(randomRule());

        List<DetectorRule> detectorRules = List.of(new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals(1, response.getHits().getTotalHits().value);

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));
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
        Map<String, Object> detectorMap = (HashMap<String, Object>)(hit.getSourceAsMap().get("detector"));
        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        assertTrue("Workflow created", ((List<String>) detectorMap.get("workflow_ids")).size() == 0);
        List workflows = getAllWorkflows();
        assertTrue("Workflow created", workflows.size() == 0);

        // Enable workflow usage and verify detector update
        updateClusterSetting(ENABLE_WORKFLOW_USAGE.getKey(), "true");
        var updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorMap = (HashMap<String, Object>)(hit.getSourceAsMap().get("detector"));

        // Verify that the workflow for the given detector is not added
        assertTrue("Workflow created", ((List<String>) detectorMap.get("workflow_ids")).size() == 0);
        workflows = getAllWorkflows();
        assertTrue("Workflow created", workflows.size() == 0);
    }

    public void testUpdateDetector_removeRule_verifyWorkflowUpdate_success() throws IOException {
        updateClusterSetting(ENABLE_WORKFLOW_USAGE.getKey(), "true");
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

        String maxRuleId =  createRule(randomAggregationRule("max", " > 3", testOpCode));
        String randomDocRuleId = createRule(randomRule());

        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId), new DetectorRule(randomDocRuleId));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals(2, response.getHits().getTotalHits().value);

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));
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
        Map<String, Object> detectorMap = (HashMap<String, Object>)(hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(3, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 3);

        // Update detector - remove one agg rule; Verify workflow
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"), Arrays.asList(new DetectorRule(randomDocRuleId)) , getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        detector = randomDetectorWithInputs(List.of(newInput));
        createResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(createResponse));
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorMap = (HashMap<String, Object>)(hit.getSourceAsMap().get("detector"));
        inputArr = (List) detectorMap.get("inputs");

        assertEquals(1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 1);

        indexDoc(index, "1", randomDoc(5, 3, testOpCode));
        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        Response executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        List<Map<String, Object>> monitorRunResults = (List<Map<String, Object>>) entityAsMap(executeResponse).get("monitor_run_results");
        assertEquals(1, monitorRunResults.size());

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults.get(0).get("input_results")).get("results")).get(0).size();
        assertEquals(6, noOfSigmaRuleMatches);

        // Verify findings
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        assertEquals(1, getFindingsBody.get("total_findings"));

        String findingDetectorId = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);

        List<Map<String, Object>> findings = (List)getFindingsBody.get("findings");

        assertEquals(1, findings.size());
        List<String> findingDocs = (List<String>) findings.get(0).get("related_doc_ids");
        Assert.assertEquals(1, findingDocs.size());
        assertTrue(Arrays.asList("1").containsAll(findingDocs));
    }

    public void testCreateDetector_workflowWithDuplicateMonitor_failure() throws IOException {
        updateClusterSetting(ENABLE_WORKFLOW_USAGE.getKey(), "true");
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

        String maxRuleId =  createRule(randomAggregationRule("max", " > 3", testOpCode));
        String randomDocRuleId = createRule(randomRule());

        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId), new DetectorRule(randomDocRuleId));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals(2, response.getHits().getTotalHits().value);

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));
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
        Map<String, Object> detectorMap = (HashMap<String, Object>)(hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(3, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 3);
    }

    public void testCreateDetector_verifyWorkflowExecutionBucketLevelDocLevelMonitors_success() throws IOException {
        updateClusterSetting(ENABLE_WORKFLOW_USAGE.getKey(), "true");
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

        String maxRuleId =  createRule(randomAggregationRule("max", " > 3", testOpCode));
        String randomDocRuleId = createRule(randomRule());

        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId), new DetectorRule(randomDocRuleId));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals(2, response.getHits().getTotalHits().value);

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));
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
        Map<String, Object> detectorMap = (HashMap<String, Object>)(hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(3, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        indexDoc(index, "1", randomDoc(5, 3, testOpCode));
        indexDoc(index, "2", randomDoc(2, 3, testOpCode));
        indexDoc(index, "3", randomDoc(4, 3, testOpCode));
        indexDoc(index, "4", randomDoc(6, 2, testOpCode));
        indexDoc(index, "5", randomDoc(1, 1, testOpCode));
        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 3);

        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        Response executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        Map<String, Object> executeWorkflowResponseMap = entityAsMap(executeResponse);
        List<Map<String, Object>> monitorRunResults = (List<Map<String, Object>>) executeWorkflowResponseMap.get("monitor_run_results");

        for (Map<String, Object> runResult : monitorRunResults) {
            if (((Map<String, Object>) runResult.get("trigger_results")).get(maxRuleId) != null) {
                assertRuleMonitorFinding(runResult, maxRuleId, 5, List.of("2", "3"));
            } else {
                int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) runResult.get("input_results")).get("results")).get(0).size();
                // 5 prepackaged and 1 custom doc level rule
                assertEquals(1, noOfSigmaRuleMatches);
            }
        }

        // Verify findings
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        assertEquals(10, getFindingsBody.get("total_findings"));

        String findingDetectorId = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);

        List<String> docLevelFinding = new ArrayList<>();
        List<Map<String, Object>> findings = (List)getFindingsBody.get("findings");

        Set<String> docLevelRules = new HashSet<>(List.of(randomDocRuleId));
        List<String> bucketLevelMonitorFindingDocs = new ArrayList<>();
        for(Map<String, Object> finding : findings) {
            List<Map<String, Object>> queries = (List<Map<String, Object>>) finding.get("queries");
            Set<String> findingRules = queries.stream().map(it -> it.get("id").toString()).collect(Collectors.toSet());
            // In this test case all doc level rules are matching the finding rule ids
            if(docLevelRules.containsAll(findingRules)) {
                docLevelFinding.addAll((List<String>) finding.get("related_doc_ids"));
            } else {
                List<String> findingDocs = (List<String>) finding.get("related_doc_ids");
                if (((Map<String, Object>) ((List<Object>) finding.get("queries")).get(0)).get("query").equals("_id:*")) {
                    Assert.assertEquals(1, findingDocs.size());
                    bucketLevelMonitorFindingDocs.addAll(findingDocs);
                } else {
                    Assert.assertEquals(4, findingDocs.size());
                    assertTrue(Arrays.asList("1", "2", "3", "4").containsAll(findingDocs));
                }
            }
        }
        assertTrue(bucketLevelMonitorFindingDocs.containsAll(Arrays.asList("1", "2", "3", "4")));
        // Verify doc level finding
        assertTrue(Arrays.asList("1", "2", "3", "4", "5").containsAll(docLevelFinding));
    }


    private static void assertRuleMonitorFinding(Map<String, Object> executeResults, String ruleId, int expectedDocCount, List<String> expectedTriggerResult) {
        List<Map<String, Object>> buckets = ((List<Map<String, Object>>)(((Map<String, Object>)((Map<String, Object>)((Map<String, Object>)((List<Object>)((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0)).get("aggregations")).get("result_agg")).get("buckets")));
        Integer docCount = buckets.stream().mapToInt(it -> (Integer)it.get("doc_count")).sum();
        assertEquals(expectedDocCount, docCount.intValue());

        List<String> triggerResultBucketKeys = ((Map<String, Object>)((Map<String, Object>) ((Map<String, Object>)executeResults.get("trigger_results")).get(ruleId)).get("agg_result_buckets")).keySet().stream().collect(Collectors.toList());
        Assert.assertEquals(expectedTriggerResult, triggerResultBucketKeys);
    }
}
