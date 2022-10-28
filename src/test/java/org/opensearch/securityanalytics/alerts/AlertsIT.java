/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.http.HttpStatus;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.junit.Assert;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.action.AlertDto;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;

import static org.opensearch.securityanalytics.TestHelpers.netFlowMappings;
import static org.opensearch.securityanalytics.TestHelpers.randomAction;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputsAndTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.randomRule;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;

public class AlertsIT extends SecurityAnalyticsRestTestCase {

    @SuppressWarnings("unchecked")
    public void testGetAlerts_success() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "windows"),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"windows\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        createAlertingMonitorConfigIndex(null);
        Action triggerAction = randomAction(createDestination());

        Detector detector = randomDetectorWithInputsAndTriggers(List.of(new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(createdId)),
                        getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(createdId), List.of(), List.of("attack.defense_evasion"), List.of(triggerAction))));

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        createdId = responseBody.get("_id").toString();

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
        Assert.assertEquals(6, noOfSigmaRuleMatches);

        Assert.assertEquals(1, ((Map<String, Object>) executeResults.get("trigger_results")).values().size());

        for (Map.Entry<String, Map<String, Object>> triggerResult: ((Map<String, Map<String, Object>>) executeResults.get("trigger_results")).entrySet()) {
            Assert.assertEquals(1, ((Map<String, Object>) triggerResult.getValue().get("action_results")).values().size());

            for (Map.Entry<String, Map<String, Object>> alertActionResult: ((Map<String, Map<String, Object>>) triggerResult.getValue().get("action_results")).entrySet()) {
                Map<String, Object> actionResults = alertActionResult.getValue();

                for (Map.Entry<String, Object> actionResult: actionResults.entrySet()) {
                    Map<String, String> actionOutput = ((Map<String, Map<String, String>>) actionResult.getValue()).get("output");
                    String expectedMessage = triggerAction.getSubjectTemplate().getIdOrCode().replace("{{ctx.detector.name}}", detector.getName())
                            .replace("{{ctx.trigger.name}}", "test-trigger").replace("{{ctx.trigger.severity}}", "1");

                    Assert.assertEquals(expectedMessage, actionOutput.get("subject"));
                    Assert.assertEquals(expectedMessage, actionOutput.get("message"));
                }
            }
        }

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = new ArrayList<>();

        while (hits.size() == 0) {
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex("windows"), request);
        }

        // Call GetAlerts API
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", createdId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        // TODO enable asserts here when able
        Assert.assertEquals(1, getAlertsBody.get("total_alerts"));
        String alertId = (String) ((ArrayList<HashMap<String, Object>>) getAlertsBody.get("alerts")).get(0).get("id");
        String detectorId = (String) ((ArrayList<HashMap<String, Object>>) getAlertsBody.get("alerts")).get(0).get("detector_id");
        params = new HashMap<>();
        String body = String.format(Locale.getDefault(), "{\"alerts\":[\"%s\"]}", alertId);
        Request post = new Request("POST", String.format(
                Locale.getDefault(),
                "%s/%s/_acknowledge/alerts",
                SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
                detectorId));
        post.setJsonEntity(body);
        Response ackAlertsResponse = client().performRequest(post);
        assertNotNull(ackAlertsResponse);
        Map<String, Object> ackAlertsResponseMap = entityAsMap(ackAlertsResponse);
        assertTrue(((ArrayList<String>) ackAlertsResponseMap.get("missing")).isEmpty());
        assertTrue(((ArrayList<AlertDto>) ackAlertsResponseMap.get("failed")).isEmpty());
        assertEquals(((ArrayList<AlertDto>) ackAlertsResponseMap.get("acknowledged")).size(), 1);
    }


    @SuppressWarnings("unchecked")
    public void testAckAlerts_WithInvalidDetectorAlertsCombination() throws IOException, InterruptedException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"windows\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        createAlertingMonitorConfigIndex(null);
        Action triggerAction = randomAction(createDestination());

        Detector detector = randomDetectorWithInputsAndTriggers(List.of(new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(),
                        getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(), List.of(), List.of("attack.defense_evasion"), List.of(triggerAction))));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        Detector detector1 = randomDetectorWithInputsAndTriggers(List.of(new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(),
                        getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(), List.of(), List.of("attack.defense_evasion"), List.of(triggerAction))));

        Response createResponse1 = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector1));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();
        String id1 = asMap(createResponse1).get("_id").toString();

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

        client().performRequest(new Request("POST", "_refresh"));

        Response executeResponse = null;

        executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = new ArrayList<>();

        while (hits.size() == 0) {
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex("windows"), request);
        }

        // Call GetAlerts API
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", createdId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        // TODO enable asserts here when able
        Assert.assertEquals(1, getAlertsBody.get("total_alerts"));
        String alertId = (String) ((ArrayList<HashMap<String, Object>>) getAlertsBody.get("alerts")).get(0).get("id");
        params = new HashMap<>();
        String body = String.format(Locale.getDefault(), "{\"alerts\":[\"%s\"]}", alertId);
        Request post = new Request("POST", String.format(
                Locale.getDefault(),
                "%s/%s/_acknowledge/alerts",
                SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
                id1));
        post.setJsonEntity(body);

        try {
            client().performRequest(post);
            fail();
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("Detector alert mapping is not valid"));
        }
    }

    public void testGetAlerts_byDetectorType_success() throws IOException, InterruptedException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"windows\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("windows"), List.of(), List.of(), List.of(), List.of())));

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

        client().performRequest(new Request("POST", "_refresh"));

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = new ArrayList<>();

        while (hits.size() == 0) {
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex("windows"), request);
        }

        // Call GetAlerts API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", Detector.DetectorType.WINDOWS.getDetectorType());
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        // TODO enable asserts here when able
        Assert.assertEquals(1, getAlertsBody.get("total_alerts"));
    }

    public void testGetAlerts_byDetectorType_multipleDetectors_success() throws IOException, InterruptedException {
        String index1 = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index1 + "\"," +
                        "  \"rule_topic\":\"windows\", " +
                        "  \"partial\":true" +
                        "}"
        );
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

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        // Detector 1 - WINDOWS
        Detector detector1 = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("windows"), List.of(), List.of(), List.of(), List.of())));
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
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("network"), List.of(), List.of(), List.of(), List.of())),
                Detector.DetectorType.NETWORK,
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
        Assert.assertEquals(3, noOfSigmaRuleMatches);

        // execute monitor 2
        executeResponse = executeAlertingMonitor(monitorId2, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        client().performRequest(new Request("POST", "_refresh"));

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = new ArrayList<>();

        while (hits.size() == 0) {
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex("windows"), request);
        }
        hits = new ArrayList<>();
        while (hits.size() == 0) {
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex("network"), request);
        }

        client().performRequest(new Request("POST", "_refresh"));

        // Call GetAlerts API for WINDOWS detector
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", Detector.DetectorType.WINDOWS.getDetectorType());
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        Assert.assertEquals(1, getAlertsBody.get("total_alerts"));
        // Call GetAlerts API for NETWORK detector
        params = new HashMap<>();
        params.put("detectorType", Detector.DetectorType.NETWORK.getDetectorType());
        getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        getAlertsBody = asMap(getAlertsResponse);
        Assert.assertEquals(1, getAlertsBody.get("total_alerts"));
    }

}