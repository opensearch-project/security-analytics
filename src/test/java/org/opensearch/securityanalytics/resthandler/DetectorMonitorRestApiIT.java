/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import static org.opensearch.securityanalytics.TestHelpers.productIndexMapping;
import static org.opensearch.securityanalytics.TestHelpers.productIndexMaxAggRule;
import static org.opensearch.securityanalytics.TestHelpers.randomAggregationRule;
import static org.opensearch.securityanalytics.TestHelpers.randomDetector;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.randomRule;
import static org.opensearch.securityanalytics.TestHelpers.sumAggregationTestRule;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
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
    public void testUpdateDetectorAddingAggregationRuleRemovingDocLevelRule() throws IOException {
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
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);
        Assert.assertEquals(5, response.getHits().getTotalHits().value);

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
        Assert.assertEquals(1, monitorIds.size());
        String monitorId = monitorIds.get(0);
        String monitorType  = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");
        Assert.assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

        // Create aggregation rules
        String sumRuleId = createRule(randomAggregationRule( "sum", " > 2"));
        String avgTermRuleId = createRule(randomAggregationRule( "avg", " > 1"));
        // Update detector and empty doc level rules so detector contains only one aggregation rule
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(sumRuleId), new DetectorRule(avgTermRuleId)),
            Collections.emptyList());
        Detector updatedDetector = randomDetectorWithInputs(List.of(input));

        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));
        Assert.assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));
        Map updateResponseBody = asMap(updateResponse);
        detectorId = updateResponseBody.get("_id").toString();

        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorAsMap = (Map<String, Object>) hit.getSourceAsMap().get("detector");
        monitorIds = (List<String>) (detectorAsMap).get("monitor_id");
        Assert.assertEquals(2, monitorIds.size());
        indexDoc(index, "1", randomDoc(2, 4));
        indexDoc(index, "2", randomDoc(3, 4));


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
        Assert.assertEquals(2, getFindingsBody.get("total_findings"));

        List<String> docIds = ((ArrayList)((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("related_doc_ids"));

        assertTrue(Arrays.asList("1", "2").containsAll(docIds));

        String findingDetectorId = ((Map<String, Object>)((List)getFindingsBody.get("findings")).get(0)).get("detectorId").toString();

        assertEquals(detectorId, findingDetectorId);
    }

    /**
     * 1. Creates detector with 1 aggregation rule and one bucket level monitor based on the aggregation rule
     * 2. Creates 5 prepackaged doc level rules and one custom doc level rule and removes the aggregation rule
     * 3. Verifies that one doc level monitor exists
     * 4. Verifies the findings
     * @throws IOException
     */
    public void testUpdateDetectorAddingDocRuleRemovingAggRule() throws IOException {
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
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(Rule.CUSTOM_RULES_INDEX, request, true);
        Assert.assertEquals(1, response.getHits().getTotalHits().value);

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
        Assert.assertEquals(MonitorType.BUCKET_LEVEL_MONITOR.getValue(), monitorType);

        // Create random doc rule and 5 pre packed rules and assign to detector
        String randomDocRuleId = createRule(randomRule());

        input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(randomDocRuleId)),
            getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector updatedDetector = randomDetectorWithInputs(List.of(input));

        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));
        Assert.assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));
        Map updateResponseBody = asMap(updateResponse);
        detectorId = updateResponseBody.get("_id").toString();

        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";

        // Verify newly created doc level monitor
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorAsMap = (Map<String, Object>) hit.getSourceAsMap().get("detector");
        monitorId = ((List<String>) (detectorAsMap).get("monitor_id")).get(0);

        monitorType  = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");
        Assert.assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);
        // Verify rules
        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);
        Assert.assertEquals(6, response.getHits().getTotalHits().value);

        response = executeSearchAndGetResponse(Rule.CUSTOM_RULES_INDEX, request, true);
        // Two custom rules - one agg and one doc level
        Assert.assertEquals(2, response.getHits().getTotalHits().value);

        // Verify findings
        indexDoc(index, "1", randomDoc(2, 5));
        indexDoc(index, "2", randomDoc(3, 5));

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        // 5 prepackaged and one custom rule
        Assert.assertEquals(6, noOfSigmaRuleMatches);
    }

    /**
     * 1. Creates detector with no rules
     * 2. Removes all doc level rules and tries to save a detector without monitor
     * 4. Verifies the findings
     * @throws IOException
     */
    public void testCreateDetectorWithoutRules() throws IOException {
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

        Detector detector = randomDetector(Collections.emptyList());

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();

        // Verify rules
        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);
        Assert.assertEquals(0, response.getHits().getTotalHits().value);

        String createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));
    }

    public void testUpdateDetectorAddingNewAggregationRule() throws IOException {
        String index = createTestIndex(randomIndex(), productIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"windows\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        String sumRuleId = createRule(sumAggregationTestRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(sumRuleId));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList());

        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(Rule.CUSTOM_RULES_INDEX, request, true);
        Assert.assertEquals(1, response.getHits().getTotalHits().value);

        // Test adding the new max monitor and updating the existing sum monitor
        String maxRuleId =  createRule(productIndexMaxAggRule());
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(maxRuleId), new DetectorRule(sumRuleId)),
            Collections.emptyList());
        Detector firstUpdatedDetector = randomDetectorWithInputs(List.of(newInput));
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(firstUpdatedDetector));
        Assert.assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));
        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> firstUpdateDetectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = firstUpdateDetectorMap.get("inputs");
        Assert.assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());
    }

    public void testUpdateDetectorDeletingExistingAggregationRule() throws IOException {
        String index = createTestIndex(randomIndex(), productIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"windows\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        List<String> aggRuleIds = createAggregationRules();
        List<DetectorRule> detectorRules = aggRuleIds.stream().map(DetectorRule::new).collect(Collectors.toList());

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            Collections.emptyList());

        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(Rule.CUSTOM_RULES_INDEX, request, true);
        Assert.assertEquals(2, response.getHits().getTotalHits().value);

        // Test deleting the aggregation rule
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(aggRuleIds.get(0))),
            Collections.emptyList());
        Detector firstUpdatedDetector = randomDetectorWithInputs(List.of(newInput));
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(firstUpdatedDetector));
        Assert.assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));
        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> firstUpdateDetectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = firstUpdateDetectorMap.get("inputs");
        Assert.assertEquals(1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());
    }

    public void testUpdateDetectorWithAggregationAndDocLevelRules() throws IOException {
        String index = createTestIndex(randomIndex(), productIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"windows\", " +
                "  \"partial\":true" +
                "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        List<String> aggRuleIds = createAggregationRules();
        List<DetectorRule> detectorRules = aggRuleIds.stream().map(DetectorRule::new).collect(Collectors.toList());

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
            getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));

        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        SearchResponse response = executeSearchAndGetResponse(Rule.CUSTOM_RULES_INDEX, request, true);
        Assert.assertEquals(2, response.getHits().getTotalHits().value);

        String maxRuleId = createRule(productIndexMaxAggRule());

        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(aggRuleIds.get(0)), new DetectorRule(maxRuleId)),
            Collections.emptyList());

        detector = randomDetectorWithInputs(List.of(newInput));
        createResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Update detector failed", RestStatus.OK, restStatus(createResponse));
        request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match_all\":{\n" +
            "     }\n" +
            "   }\n" +
            "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> firstUpdateDetectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = firstUpdateDetectorMap.get("inputs");
        Assert.assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());
    }
}
