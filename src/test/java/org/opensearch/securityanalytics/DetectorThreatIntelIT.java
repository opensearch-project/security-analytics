/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputsAndThreatIntel;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputsAndThreatIntelAndTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomDocWithIpIoc;
import static org.opensearch.securityanalytics.TestHelpers.randomDocWithNullField;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.randomNullRule;
import static org.opensearch.securityanalytics.TestHelpers.randomRule;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE;

public class DetectorThreatIntelIT extends SecurityAnalyticsRestTestCase {

    public void testCreateDetectorWithThreatIntelEnabled_updateDetectorWithThreatIntelDisabled() throws IOException {

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

        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        DetectorTrigger trigger = new DetectorTrigger("all", "all", "high", List.of(randomDetectorType()), emptyList(), emptyList(), List.of(), emptyList(), List.of(DetectorTrigger.RULES_DETECTION_TYPE, DetectorTrigger.THREAT_INTEL_DETECTION_TYPE));
        Detector detector = randomDetectorWithInputsAndThreatIntelAndTriggers(List.of(input), true, List.of(trigger));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()) + "*", request, true);


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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");


        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 1);
        List<String> iocs = getThreatIntelFeedIocs(3);
        int i = 1;
        for (String ioc : iocs) {
            indexDoc(index, i + "", randomDocWithIpIoc(5, 3, ioc));
            i++;
        }
        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        Response executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        List<Map<String, Object>> monitorRunResults = (List<Map<String, Object>>) entityAsMap(executeResponse).get("monitor_run_results");
        assertEquals(1, monitorRunResults.size());

        Map<String, Object> docLevelQueryResults = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults.get(0).get("input_results")).get("results")).get(0);
        int noOfSigmaRuleMatches = docLevelQueryResults.size();
        assertEquals(2, noOfSigmaRuleMatches);
        String threatIntelDocLevelQueryId = docLevelQueryResults.keySet().stream().filter(id -> id.startsWith("threat_intel")).findAny().get();
        ArrayList<String> docs = (ArrayList<String>) docLevelQueryResults.get(threatIntelDocLevelQueryId);
        assertEquals(docs.size(), 3);
        //verify alerts
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);

        Assert.assertEquals(3, getAlertsBody.get("total_alerts"));

        // update detector
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(randomDetectorWithInputsAndThreatIntel(List.of(input), false)));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        Map<String, Object> updateResponseBody = asMap(updateResponse);
        for (String ioc : iocs) {
            indexDoc(index, i + "", randomDocWithIpIoc(5, 3, ioc));
            i++;
        }

        executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        monitorRunResults = (List<Map<String, Object>>) entityAsMap(executeResponse).get("monitor_run_results");
        assertEquals(1, monitorRunResults.size());

        docLevelQueryResults = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults.get(0).get("input_results")).get("results")).get(0);
        noOfSigmaRuleMatches = docLevelQueryResults.size();
        assertEquals(1, noOfSigmaRuleMatches);
    }

    public void testCreateDetectorForSigmaRuleWithNullCondition() throws IOException {

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

        String randomDocRuleId = createRule(randomNullRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        DetectorTrigger trigger = new DetectorTrigger("all", "all", "high", List.of(randomDetectorType()), emptyList(), emptyList(), List.of(), emptyList(), List.of(DetectorTrigger.RULES_DETECTION_TYPE, DetectorTrigger.THREAT_INTEL_DETECTION_TYPE));
        Detector detector = randomDetectorWithInputs(List.of(input));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";

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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");


        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        Response getMonitorResponse = getAlertingMonitor(client(), monitorIds.get(0));
        Map<String, Object> alertingMonitor = asMap(getMonitorResponse);
        assertNotNull(alertingMonitor);
        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        indexDoc(index, "1", randomDocWithNullField());
        indexDoc(index, "2", randomDoc());

        Response executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        List<Map<String, Object>> monitorRunResults = (List<Map<String, Object>>) entityAsMap(executeResponse).get("monitor_run_results");
        assertEquals(1, monitorRunResults.size());

        Map<String, Object> docLevelQueryResults = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults.get(0).get("input_results")).get("results")).get(0);
        int noOfSigmaRuleMatches = docLevelQueryResults.size();
        assertEquals(1, noOfSigmaRuleMatches);
        String queryId = docLevelQueryResults.keySet().stream().findAny().get();
        ArrayList<String> docs = (ArrayList<String>) docLevelQueryResults.get(queryId);
        assertEquals(docs.size(), 1);

        indexDoc(index, "3", randomDoc());
        Response executeResponse1 = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        List<Map<String, Object>> monitorRunResults1 = (List<Map<String, Object>>) entityAsMap(executeResponse1).get("monitor_run_results");
        assertEquals(1, monitorRunResults1.size());

        Map<String, Object> docLevelQueryResults1 = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults1.get(0).get("input_results")).get("results")).get(0);
        int noOfSigmaRuleMatches1 = docLevelQueryResults1.size();
        assertEquals(0, noOfSigmaRuleMatches1);

    }

    public void testCreateDetectorWithThreatIntelDisabled_updateDetectorWithThreatIntelEnabled() throws IOException {

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

        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        Detector detector = randomDetectorWithInputsAndThreatIntel(List.of(input), false);
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()) + "*", request, true);


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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");


        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 1);
        indexDoc(index, "1", randomDoc(2, 4, "test"));
        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        Response executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        List<Map<String, Object>> monitorRunResults = (List<Map<String, Object>>) entityAsMap(executeResponse).get("monitor_run_results");
        assertEquals(1, monitorRunResults.size());
        Map<String, Object> docLevelQueryResults = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults.get(0).get("input_results")).get("results")).get(0);
        int noOfSigmaRuleMatches = docLevelQueryResults.size();
        assertEquals(1, noOfSigmaRuleMatches);

        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(randomDetectorWithInputsAndThreatIntel(List.of(input), true)));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        Map<String, Object> updateResponseBody = asMap(updateResponse);
        List<String> iocs = getThreatIntelFeedIocs(3);
        int i = 2;
        for (String ioc : iocs) {
            indexDoc(index, i + "", randomDocWithIpIoc(5, 3, ioc));
            i++;
        }
        executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        monitorRunResults = (List<Map<String, Object>>) entityAsMap(executeResponse).get("monitor_run_results");
        assertEquals(1, monitorRunResults.size());

        docLevelQueryResults = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults.get(0).get("input_results")).get("results")).get(0);
        noOfSigmaRuleMatches = docLevelQueryResults.size();
        assertEquals(2, noOfSigmaRuleMatches);
    }

    public void testCreateDetectorWithThreatIntelEnabledAndNoRules_triggerDetectionTypeOnlyRules_noAlertsForFindings() throws IOException {

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


        List<DetectorRule> detectorRules = emptyList();
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        DetectorTrigger trigger = new DetectorTrigger("all", "all", "high", List.of(randomDetectorType()), emptyList(), emptyList(), List.of(), emptyList(), List.of(DetectorTrigger.RULES_DETECTION_TYPE));
        Detector detector = randomDetectorWithInputsAndThreatIntelAndTriggers(List.of(input), true, List.of(trigger));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()) + "*", request, true);


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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");


        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 1);
        List<String> iocs = getThreatIntelFeedIocs(3);
        int i = 1;
        for (String ioc : iocs) {
            indexDoc(index, i + "", randomDocWithIpIoc(5, 3, ioc));
            i++;
        }
        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        Response executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        List<Map<String, Object>> monitorRunResults = (List<Map<String, Object>>) entityAsMap(executeResponse).get("monitor_run_results");
        assertEquals(1, monitorRunResults.size());

        Map<String, Object> docLevelQueryResults = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults.get(0).get("input_results")).get("results")).get(0);
        int noOfSigmaRuleMatches = docLevelQueryResults.size();
        assertEquals(1, noOfSigmaRuleMatches);
        String threatIntelDocLevelQueryId = docLevelQueryResults.keySet().stream().filter(id -> id.startsWith("threat_intel")).findAny().get();
        ArrayList<String> docs = (ArrayList<String>) docLevelQueryResults.get(threatIntelDocLevelQueryId);
        assertEquals(docs.size(), 3);
        //verify alerts
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        /** findings are present but alerts should not be generated as detection type mentioned in trigger is rules only */
        Assert.assertEquals(0, getAlertsBody.get("total_alerts"));
    }

    public void testCreateDetectorWithThreatIntelEnabled_triggerDetectionTypeOnlyThreatIntel_allAlertsForFindings() throws IOException {

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


        List<DetectorRule> detectorRules = emptyList();
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        DetectorTrigger trigger = new DetectorTrigger("all", "all", "high",
                List.of(randomDetectorType()), emptyList(), emptyList(), List.of(), emptyList(), List.of(DetectorTrigger.THREAT_INTEL_DETECTION_TYPE));
        Detector detector = randomDetectorWithInputsAndThreatIntelAndTriggers(List.of(input), true, List.of(trigger));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()) + "*", request, true);


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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");


        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 1);
        List<String> iocs = getThreatIntelFeedIocs(3);
        int i = 1;
        for (String ioc : iocs) {
            indexDoc(index, i + "", randomDocWithIpIoc(5, 3, ioc));
            i++;
        }
        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        Response executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        List<Map<String, Object>> monitorRunResults = (List<Map<String, Object>>) entityAsMap(executeResponse).get("monitor_run_results");
        assertEquals(1, monitorRunResults.size());

        Map<String, Object> docLevelQueryResults = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults.get(0).get("input_results")).get("results")).get(0);
        int noOfSigmaRuleMatches = docLevelQueryResults.size();
        assertEquals(1, noOfSigmaRuleMatches);
        String threatIntelDocLevelQueryId = docLevelQueryResults.keySet().stream().filter(id -> id.startsWith("threat_intel")).findAny().get();
        ArrayList<String> docs = (ArrayList<String>) docLevelQueryResults.get(threatIntelDocLevelQueryId);
        assertEquals(docs.size(), 3);
        //verify alerts
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        /** findings are present and alerts are generated as detection type mentioned in trigger is threat_intel only */
        Assert.assertEquals(3, getAlertsBody.get("total_alerts"));
    }

    public void testCreateDetectorWithThreatIntelEnabled_triggerWithBothDetectionType_allAlertsForFindings() throws IOException {

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


        List<DetectorRule> detectorRules = emptyList();
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        DetectorTrigger trigger = new DetectorTrigger("all", "all", "high",
                List.of(randomDetectorType()), emptyList(), emptyList(), List.of(), emptyList(),
                List.of(DetectorTrigger.THREAT_INTEL_DETECTION_TYPE, DetectorTrigger.RULES_DETECTION_TYPE));
        Detector detector = randomDetectorWithInputsAndThreatIntelAndTriggers(List.of(input), true, List.of(trigger));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()) + "*", request, true);


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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");


        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 1);
        List<String> iocs = getThreatIntelFeedIocs(3);
        int i = 1;
        for (String ioc : iocs) {
            indexDoc(index, i + "", randomDocWithIpIoc(5, 3, ioc));
            i++;
        }
        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        Response executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        List<Map<String, Object>> monitorRunResults = (List<Map<String, Object>>) entityAsMap(executeResponse).get("monitor_run_results");
        assertEquals(1, monitorRunResults.size());

        Map<String, Object> docLevelQueryResults = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults.get(0).get("input_results")).get("results")).get(0);
        int noOfSigmaRuleMatches = docLevelQueryResults.size();
        assertEquals(1, noOfSigmaRuleMatches);
        String threatIntelDocLevelQueryId = docLevelQueryResults.keySet().stream().filter(id -> id.startsWith("threat_intel")).findAny().get();
        ArrayList<String> docs = (ArrayList<String>) docLevelQueryResults.get(threatIntelDocLevelQueryId);
        assertEquals(docs.size(), 3);
        //verify alerts
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        /** findings are present and alerts are generated as both detection type mentioned in trigger is threat_intel only */
        Assert.assertEquals(3, getAlertsBody.get("total_alerts"));
    }

    public void testCreateDetectorWithThreatIntelDisabled_triggerWithThreatIntelDetectionType_mpAlertsForFindings() throws IOException {

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
        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        DetectorTrigger trigger = new DetectorTrigger("all", "all", "high",
                List.of(randomDetectorType()), emptyList(), emptyList(), List.of(), emptyList(),
                List.of(DetectorTrigger.THREAT_INTEL_DETECTION_TYPE));
        Detector detector = randomDetectorWithInputsAndThreatIntelAndTriggers(List.of(input), false, List.of(trigger));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()) + "*", request, true);


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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");


        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 1);

        int i = 1;
        while (i < 4) {
            indexDoc(index, i + "", randomDocWithIpIoc(5, 3, i + ""));
            i++;
        }
        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        Response executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        List<Map<String, Object>> monitorRunResults = (List<Map<String, Object>>) entityAsMap(executeResponse).get("monitor_run_results");
        assertEquals(1, monitorRunResults.size());

        Map<String, Object> docLevelQueryResults = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults.get(0).get("input_results")).get("results")).get(0);
        int noOfSigmaRuleMatches = docLevelQueryResults.size();
        assertEquals(1, noOfSigmaRuleMatches);
        String ruleQueryId = docLevelQueryResults.keySet().stream().findAny().get();
        ArrayList<String> docs = (ArrayList<String>) docLevelQueryResults.get(ruleQueryId);
        assertEquals(docs.size(), 3);
        //verify alerts
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        /** findings are present but alerts are NOT generated as  detection type mentioned in trigger is threat_intel only but finding is from rules*/
        Assert.assertEquals(0, getAlertsBody.get("total_alerts"));
    }

    public void testCreateDetectorWithThreatIntelDisabled_triggerWithRulesDetectionType_allAlertsForFindings() throws IOException {

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
        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        DetectorTrigger trigger = new DetectorTrigger("all", "all", "high",
                List.of(randomDetectorType()), emptyList(), emptyList(), List.of(), emptyList(),
                List.of(DetectorTrigger.RULES_DETECTION_TYPE));
        Detector detector = randomDetectorWithInputsAndThreatIntelAndTriggers(List.of(input), false, List.of(trigger));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()) + "*", request, true);


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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");


        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 1);

        int i = 1;
        while (i < 4) {
            indexDoc(index, i + "", randomDocWithIpIoc(5, 3, i + ""));
            i++;
        }
        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        Response executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        List<Map<String, Object>> monitorRunResults = (List<Map<String, Object>>) entityAsMap(executeResponse).get("monitor_run_results");
        assertEquals(1, monitorRunResults.size());

        Map<String, Object> docLevelQueryResults = ((List<Map<String, Object>>) ((Map<String, Object>) monitorRunResults.get(0).get("input_results")).get("results")).get(0);
        int noOfSigmaRuleMatches = docLevelQueryResults.size();
        assertEquals(1, noOfSigmaRuleMatches);
        String ruleQueryId = docLevelQueryResults.keySet().stream().findAny().get();
        ArrayList<String> docs = (ArrayList<String>) docLevelQueryResults.get(ruleQueryId);
        assertEquals(docs.size(), 3);
        //verify alerts
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        /** findings are present but alerts are NOT generated as  detection type mentioned in trigger is threat_intel only but finding is from rules*/
        Assert.assertEquals(3, getAlertsBody.get("total_alerts"));
    }
}