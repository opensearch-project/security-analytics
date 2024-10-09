/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.findings;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Ignore;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;

import static java.util.Collections.emptyList;
import static org.opensearch.securityanalytics.TestHelpers.netFlowMappings;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;
import static org.opensearch.securityanalytics.TestHelpers.randomRuleWithNotConditionBoolAndNum;
import static org.opensearch.securityanalytics.TestHelpers.randomNetworkDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomDocForNotCondition;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;
import static org.opensearch.securityanalytics.TestHelpers.randomRuleWithNotCondition;
import static org.opensearch.securityanalytics.TestHelpers.randomRule;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputsAndThreatIntel;
import static org.opensearch.securityanalytics.TestHelpers.randomRuleWithCriticalSeverity;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_INDEX_MAX_AGE;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_MAX_DOCS;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_RETENTION_PERIOD;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_ROLLOVER_PERIOD;

public class FindingIT extends SecurityAnalyticsRestTestCase {

    @SuppressWarnings("unchecked")
    public void testGetFindings_byDetectorId_success() throws IOException {
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

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of(), List.of())));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        String monitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index, "1", randomDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", createdId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
    }

    public void testGetFindings_noDetector_failure() throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", "nonexistent_id");
        try {
            makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_NOT_FOUND, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    public void testGetFindings_byDetectorType_oneDetector_success() throws IOException {
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

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of(), List.of())));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        String monitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index, "1", randomDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", detector.getDetectorType());
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
    }

    public void testGetFindings_byDetectorType_success() throws IOException {
        String index1 = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index1 + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // index 2
        String index2 = createTestIndex("netflow_test", netFlowMappings());

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index2 + "\"," +
                        "  \"rule_topic\":\"netflow\", " +
                        "  \"partial\":true" +
                        "}"
        );

        response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        // Detector 1 - WINDOWS
        Detector detector1 = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of(), List.of())));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector1));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        String monitorId1 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
        // Detector 2 - NETWORK
        DetectorInput inputNetflow = new DetectorInput("windows detector for security analytics", List.of("netflow_test"), Collections.emptyList(),
                getPrePackagedRules("network").stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector2 = randomDetectorWithTriggers(
                getPrePackagedRules("network"),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("network"), List.of(), List.of(), List.of(), List.of(), List.of())),
                "network",
                inputNetflow
        );

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector2));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        createdId = responseBody.get("_id").toString();

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        String monitorId2 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index1, "1", randomDoc());
        indexDoc(index2, "1", randomNetworkDoc());
        // execute monitor 1
        Response executeResponse = executeAlertingMonitor(monitorId1, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);

        // execute monitor 2
        executeResponse = executeAlertingMonitor(monitorId2, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);

        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        // client().performRequest(new Request("POST", "_refresh"));

        // Call GetFindings API for first detector
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", detector1.getDetectorType());
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
        // Call GetFindings API for second detector
        params.clear();
        params.put("detectorType", detector2.getDetectorType());
        getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
    }

    public void testGetAllFindings_success() throws IOException {
        String index1 = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index1 + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // index 2
        String index2 = createTestIndex("netflow_test", netFlowMappings());

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index2 + "\"," +
                        "  \"rule_topic\":\"netflow\", " +
                        "  \"partial\":true" +
                        "}"
        );

        response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        // Detector 1 - WINDOWS
        Detector detector1 = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of(), List.of())));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector1));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        String monitorId1 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
        // Detector 2 - NETWORK
        DetectorInput inputNetflow = new DetectorInput("windows detector for security analytics", List.of("netflow_test"), Collections.emptyList(),
                getPrePackagedRules("network").stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector2 = randomDetectorWithTriggers(
                getPrePackagedRules("network"),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("network"), List.of(), List.of(), List.of(), List.of(), List.of())),
                "network",
                inputNetflow
        );

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector2));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        createdId = responseBody.get("_id").toString();

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        String monitorId2 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index1, "1", randomDoc());
        indexDoc(index2, "1", randomDoc());
        // execute monitor 1
        Response executeResponse = executeAlertingMonitor(monitorId1, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);

        // execute monitor 2
        executeResponse = executeAlertingMonitor(monitorId2, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);

        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        // Assert.assertEquals(1, noOfSigmaRuleMatches);

        // client().performRequest(new Request("POST", "_refresh"));

        // Call GetFindings API for all the detectors
        Map<String, String> params = new HashMap<>();
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
    }

    public void testGetFindings_byDetectionType_success() throws IOException {
        String index1 = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index1 + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // index 2
        String index2 = createTestIndex("netflow_test", netFlowMappings());

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index2 + "\"," +
                        "  \"rule_topic\":\"netflow\", " +
                        "  \"partial\":true" +
                        "}"
        );

        response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        // Detector 1 - WINDOWS
        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        Detector detector1 =  randomDetectorWithInputsAndThreatIntel(List.of(input), true);

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector1));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        String monitorId1 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
        // Detector 2 - NETWORK
        DetectorInput inputNetflow = new DetectorInput("windows detector for security analytics", List.of("netflow_test"), Collections.emptyList(),
                getPrePackagedRules("network").stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector2 = randomDetectorWithTriggers(
                getPrePackagedRules("network"),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("network"), List.of(), List.of(), List.of(), List.of(), List.of())),
                "network",
                inputNetflow
        );

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector2));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        createdId = responseBody.get("_id").toString();

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        String monitorId2 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index1, "1", randomDoc());
        indexDoc(index2, "1", randomDoc());
        // execute monitor 1
        Response executeResponse = executeAlertingMonitor(monitorId1, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        // execute monitor 2
        executeResponse = executeAlertingMonitor(monitorId2, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);

        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        // Assert.assertEquals(1, noOfSigmaRuleMatches);

        // Call GetFindings API for first detector by detectionType
        Map<String, String> params = new HashMap<>();
        params.put("detectionType", "rule");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
    }

    public void testGetFindings_bySeverity_success() throws IOException {
        String index1 = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index1 + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // index 2
        String index2 = createTestIndex("windows1", windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index2 + "\"," +
                        "  \"rule_topic\":\"windows\", " +
                        "  \"partial\":true" +
                        "}"
        );

        response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        // Detector 1 - WINDOWS
        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        Detector detector1 =  randomDetectorWithTriggers(
                getPrePackagedRules("windows"),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("windows"), List.of(), List.of(), List.of(), List.of(), List.of())),
                "windows",
                input
        );

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector1));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        String monitorId1 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
        // Detector 2 - CRITICAL Severity Netflow
        String randomDocRuleId2 = createRule(randomRuleWithCriticalSeverity());
        List<DetectorRule> detectorRules2 = List.of(new DetectorRule(randomDocRuleId2));
        DetectorInput inputNetflow = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules2,
                emptyList());
        Detector detector2 = randomDetectorWithTriggers(
                getPrePackagedRules("windows1"),
                List.of(new DetectorTrigger(null, "test-trigger", "0", List.of("windows1"), List.of(), List.of(), List.of(), List.of(), List.of())),
                "windows",
                inputNetflow
        );

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector2));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        logger.info("Created response 2 : {}", responseBody.toString());

        createdId = responseBody.get("_id").toString();

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        String monitorId2 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index1, "1", randomDoc());
        indexDoc(index2, "2", randomDoc());
        // execute monitor 1
        Response executeResponse = executeAlertingMonitor(monitorId1, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        // execute monitor 2
        executeResponse = executeAlertingMonitor(monitorId2, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        // client().performRequest(new Request("POST", "_refresh"));

        // Call GetFindings API for first detector by severity
        Map<String, String> params = new HashMap<>();
        params.put("severity", "high");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
        // Call GetFindings API for second detector by severity
        params.clear();
        params.put("severity", "critical");
        getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
    }

    @Ignore
    public void testGetFindings_bySearchString_success() throws IOException {
        String index1 = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index1 + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // index 2
        String index2 = createTestIndex("windows1", windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index2 + "\"," +
                        "  \"rule_topic\":\"windows\", " +
                        "  \"partial\":true" +
                        "}"
        );

        response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        // Detector 1 - WINDOWS
        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        Detector detector1 =  randomDetectorWithTriggers(
                getPrePackagedRules("windows"),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("windows"), List.of(), List.of(), List.of(), List.of(), List.of())),
                "windows",
                input
        );

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector1));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        String monitorId1 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
        // Detector 2 - CRITICAL Severity Netflow
        String randomDocRuleId2 = createRule(randomRuleWithCriticalSeverity());
        List<DetectorRule> detectorRules2 = List.of(new DetectorRule(randomDocRuleId2));
        DetectorInput inputNetflow = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules2,
                emptyList());
        Detector detector2 = randomDetectorWithTriggers(
                getPrePackagedRules("windows1"),
                List.of(new DetectorTrigger(null, "test-trigger", "0", List.of("windows1"), List.of(), List.of(), List.of(), List.of(), List.of())),
                "windows",
                inputNetflow
        );

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector2));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        logger.info("Created response 2 : {}", responseBody.toString());

        createdId = responseBody.get("_id").toString();

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        String monitorId2 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index1, "1", randomDoc());
        indexDoc(index2, "2", randomDoc());
        // execute monitor 1
        Response executeResponse = executeAlertingMonitor(monitorId1, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        // execute monitor 2
        executeResponse = executeAlertingMonitor(monitorId2, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        // client().performRequest(new Request("POST", "_refresh"));

        // Call GetFindings API for first detector by searchString 'high'
        Map<String, String> params = new HashMap<>();
        params.put("searchString", "high");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(2, getFindingsBody.get("total_findings"));
        // Call GetFindings API for second detector by searchString 'critical'
        params.clear();
        params.put("searchString", "critical");
        getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(2, getFindingsBody.get("total_findings"));
    }

    @Ignore
    public void testGetFindings_byStartTimeAndEndTime_success() throws IOException {
        String index1 = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index1 + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // index 2
        String index2 = createTestIndex("windows1", windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index2 + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        // Detector 1 - WINDOWS
        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of(index1), detectorRules,
                emptyList());
        Detector detector1 =  randomDetectorWithTriggers(
                getPrePackagedRules(randomDetectorType()),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(index1), List.of(), List.of(), List.of(), List.of(), List.of())),
                randomDetectorType(),
                input
        );

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector1));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        String monitorId1 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
        // Detector 2 - CRITICAL Severity Netflow
        String randomDocRuleId2 = createRule(randomRuleWithCriticalSeverity());
        List<DetectorRule> detectorRules2 = List.of(new DetectorRule(randomDocRuleId2));
        DetectorInput inputNetflow = new DetectorInput("windows detector for security analytics", List.of(index2), detectorRules2,
                emptyList());
        Detector detector2 = randomDetectorWithTriggers(
                getPrePackagedRules(randomDetectorType()),
                List.of(new DetectorTrigger(null, "test-trigger", "0", List.of(index2), List.of(), List.of(), List.of(), List.of(), List.of())),
                randomDetectorType(),
                inputNetflow
        );

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector2));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        logger.info("Created response 2 : {}", responseBody.toString());

        createdId = responseBody.get("_id").toString();

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        String monitorId2 = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        Instant startTime1 = Instant.now();
        indexDoc(index1, "1", randomDoc());
        indexDoc(index2, "2", randomDoc());
        // execute monitor 1
        Response executeResponse = executeAlertingMonitor(monitorId1, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        // client().performRequest(new Request("POST", "_refresh"));
        // Call GetFindings API for first detector by startTime and endTime
        Map<String, String> params = new HashMap<>();
        params.put("startTime", String.valueOf(startTime1.toEpochMilli()));
        Instant endTime1 = Instant.now();
        params.put("endTime", String.valueOf(endTime1.toEpochMilli()));
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);

        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));

        // client().performRequest(new Request("POST", "_refresh"));
        Instant startTime2 = Instant.now();
        // execute monitor 2
        executeResponse = executeAlertingMonitor(monitorId2, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        // Call GetFindings API for second detector by startTime and endTime
        params.clear();
        params.put("startTime", String.valueOf(startTime2.toEpochMilli()));
        Instant endTime2 = Instant.now();
        params.put("endTime", String.valueOf(endTime2.toEpochMilli()));
        getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
    }

    @Ignore
    public void testGetFindings_rolloverByMaxAge_success() throws IOException, InterruptedException {

        updateClusterSetting(FINDING_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(FINDING_HISTORY_INDEX_MAX_AGE.getKey(), "1s");

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

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of(), List.of())));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        String monitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        // Execute monitor first time to create findings index/alias
        indexDoc(index, "1", randomDoc());
        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());

        // Wait for findings index to rollover first, to make sure that our rollover applied correct settings/mappings
        List<String> findingIndices = getFindingIndices(detector.getDetectorType());
        while(findingIndices.size() < 2) {
            findingIndices = getFindingIndices(detector.getDetectorType());
            Thread.sleep(1000);
        }
        assertTrue("Did not find more then 2 finding indices", findingIndices.size() >= 2);

        // Execute monitor second time to insert finding in new rollover'd index
        indexDoc(index, "2", randomDoc());
        executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        // Assert.assertEquals(1, getFindingsBody.get("total_findings"));

        restoreAlertsFindingsIMSettings();
    }

    @Ignore
    public void testGetFindings_rolloverByMaxDoc_success() throws IOException, InterruptedException {

        updateClusterSetting(FINDING_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(FINDING_HISTORY_MAX_DOCS.getKey(), "1");

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

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of(), List.of())));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        String monitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index, "1", randomDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));

        List<String> findingIndices = getFindingIndices(detector.getDetectorType());
        while(findingIndices.size() < 2) {
            findingIndices = getFindingIndices(detector.getDetectorType());
            Thread.sleep(1000);
        }
        assertTrue("Did not find 3 alert indices", findingIndices.size() >= 2);

        restoreAlertsFindingsIMSettings();
    }

    @Ignore
    public void testCreateDetectorWithNotCondition_verifyFindings_success() throws IOException {
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

        // Create random doc rule
        String randomDocRuleId = createRule(randomRuleWithNotCondition());
        List<String> prepackagedRules = getRandomPrePackagedRules();
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(randomDocRuleId)),
                prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map updateResponseBody = asMap(createResponse);
        String detectorId = updateResponseBody.get("_id").toString();
        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";

        // Verify newly created doc level monitor
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, Object> detectorAsMap = (Map<String, Object>) hit.getSourceAsMap().get("detector");
        List<String> monitorIds = ((List<String>) (detectorAsMap).get("monitor_id"));

        assertEquals(1, monitorIds.size());

        String monitorId = monitorIds.get(0);
        String monitorType = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");

        assertEquals(Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

        // Verify rules
        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals(6, response.getHits().getTotalHits().value);

        // Verify findings
        indexDoc(index, "1", randomDoc(2, 5, "Test"));
        indexDoc(index, "2", randomDoc(3, 5, "Test"));


        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        // Verify 5 prepackaged rules and 1 custom rule
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

        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");
        List<String> foundDocIds = new ArrayList<>();
        for (Map<String, Object> finding : findings) {
            Set<String> aggRulesFinding = ((List<Map<String, Object>>) finding.get("queries")).stream().map(it -> it.get("id").toString()).collect(
                    Collectors.toSet());

            assertTrue(docRuleIds.containsAll(aggRulesFinding));

            List<String> findingDocs = (List<String>) finding.get("related_doc_ids");
            Assert.assertEquals(1, findingDocs.size());
            foundDocIds.addAll(findingDocs);
        }
        assertTrue(Arrays.asList("1", "2").containsAll(foundDocIds));
    }

    @Ignore
    public void testCreateDetectorWithNotCondition_verifyFindings_success_boolAndNum() throws IOException {
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

        // Create random custom doc rule with NOT condition
        String randomDocRuleId = createRule(randomRuleWithNotConditionBoolAndNum());
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(randomDocRuleId)),
                emptyList());
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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");

        assertEquals(1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        String monitorId = monitorIds.get(0);

        // Verify findings
        indexDoc(index, "1", randomDoc(2, 5, "Test"));
        indexDoc(index, "2", randomDoc(2, 5, "Test"));


        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();

        // Verify 1 custom rule
        assertEquals(1, noOfSigmaRuleMatches);

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        // When doc level monitor is being applied one finding is generated per document
        assertEquals(2, getFindingsBody.get("total_findings"));

        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");
        List<String> foundDocIds = new ArrayList<>();
        for (Map<String, Object> finding : findings) {
            List<String> findingDocs = (List<String>) finding.get("related_doc_ids");
            Assert.assertEquals(1, findingDocs.size());
            foundDocIds.addAll(findingDocs);
        }
        assertTrue(Arrays.asList("1", "2").containsAll(foundDocIds));
    }

    /*
    Create a detector with custom rules that include a "not" condition in the sigma rule.
    Insert two test documents one matching the rule and one without the field matching the condition to generate only one finding
 */
    public void testCreateDetectorWithNotCondition_verifyFindingsAndNoFindings_success() throws IOException {
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

        // Create random custom doc rule with NOT condition
        String randomDocRuleId = createRule(randomRuleWithNotCondition());
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(randomDocRuleId)),
                emptyList());
        Detector detector = randomDetectorWithInputs(List.of(input));

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

        assertEquals(1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(1, monitorIds.size());

        String monitorId = monitorIds.get(0);

        // Verify findings
        indexDoc(index, "1", randomDoc(2, 5, "Test"));
        indexDoc(index, "2", randomDocForNotCondition(2, 5, "Test"));
        indexDoc(index, "3", randomDocForNotCondition(2, 5, "Test"));
        indexDoc(index, "4", randomDoc(2, 5, "Test"));

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();

        // Verify 1 custom rule
        assertEquals(1, noOfSigmaRuleMatches);

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        response = executeSearchAndGetResponse(DetectorMonitorConfig.getFindingsIndex(randomDetectorType()), request, true);

        assertEquals(2, response.getHits().getTotalHits().value);

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        // When doc level monitor is being applied one finding is generated per document
        assertEquals(2, getFindingsBody.get("total_findings"));

        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");
        List<String> foundDocIds = new ArrayList<>();
        for (Map<String, Object> finding : findings) {
            List<String> findingDocs = (List<String>) finding.get("related_doc_ids");
            Assert.assertEquals(1, findingDocs.size());
            foundDocIds.addAll(findingDocs);
        }
        assertTrue(Arrays.asList("1", "4").containsAll(foundDocIds));
    }

    @Ignore
    public void testGetFindings_rolloverByMaxDoc_short_retention_success() throws IOException, InterruptedException {
        updateClusterSetting(FINDING_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(FINDING_HISTORY_MAX_DOCS.getKey(), "1");

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

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of(), List.of())));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        String monitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index, "1", randomDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        // client().performRequest(new Request("POST", "_refresh"));
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));

        List<String> findingIndices = getFindingIndices(detector.getDetectorType());
        while(findingIndices.size() < 2) {
            findingIndices = getFindingIndices(detector.getDetectorType());
            Thread.sleep(1000);
        }
        assertTrue("Did not find 3 findings indices", findingIndices.size() >= 2);

        updateClusterSetting(FINDING_HISTORY_RETENTION_PERIOD.getKey(), "1s");
        updateClusterSetting(FINDING_HISTORY_MAX_DOCS.getKey(), "1000");
        while(findingIndices.size() != 1) {
            findingIndices = getFindingIndices(detector.getDetectorType());
            Thread.sleep(1000);
        }

        assertTrue("Found finding indices but expected none", findingIndices.size() == 1);

        // Exec monitor again to make sure that current
        indexDoc(index, "2", randomDoc());

        executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);

        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
        // client().performRequest(new Request("POST", "_refresh"));
        getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));

        restoreAlertsFindingsIMSettings();
    }
}
