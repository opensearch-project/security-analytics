/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import org.apache.http.HttpStatus;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.junit.Assert;
import org.junit.Ignore;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.action.AlertDto;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import static org.opensearch.securityanalytics.TestHelpers.netFlowMappings;
import static org.opensearch.securityanalytics.TestHelpers.randomAction;
import static org.opensearch.securityanalytics.TestHelpers.randomAggregationRule;
import static org.opensearch.securityanalytics.TestHelpers.randomDetector;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputsAndTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomNetworkDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.randomRule;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_INDEX_MAX_AGE;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_MAX_DOCS;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_RETENTION_PERIOD;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_ROLLOVER_PERIOD;

public class AlertsIT extends SecurityAnalyticsRestTestCase {

    @SuppressWarnings("unchecked")
    public void testGetAlerts_success() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

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

        createAlertingMonitorConfigIndex(null);
        Action triggerAction = randomAction(createDestination());

        Detector detector = randomDetectorWithInputsAndTriggers(List.of(new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(createdId)),
                        getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(createdId), List.of(), List.of("attack.defense_evasion"), List.of(triggerAction), List.of())));

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
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex(randomDetectorType()), request);
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

    @Ignore
    @SuppressWarnings("unchecked")
    public void testGetAlertsByStartTimeAndEndTimeSuccess() throws IOException, InterruptedException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

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

        createAlertingMonitorConfigIndex(null);
        Action triggerAction = randomAction(createDestination());

        Detector detector = randomDetectorWithInputsAndTriggers(List.of(new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(createdId)),
                        getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(createdId), List.of(), List.of("attack.defense_evasion"), List.of(triggerAction), List.of())));

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        final String detectorId = responseBody.get("_id").toString();

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
        Assert.assertEquals(6, noOfSigmaRuleMatches);

        Assert.assertEquals(1, ((Map<String, Object>) executeResults.get("trigger_results")).values().size());

        // Call GetAlerts API
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        // TODO enable asserts here when able
        Assert.assertEquals(1, getAlertsBody.get("total_alerts"));

        Instant startTime = Instant.now();
        indexDoc(index, "2", randomDoc());
        indexDoc(index, "5", randomDoc());

        executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);

        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(6, noOfSigmaRuleMatches);

        Assert.assertEquals(1, ((Map<String, Object>) executeResults.get("trigger_results")).values().size());
        Instant endTime = Instant.now();

        indexDoc(index, "4", randomDoc());
        indexDoc(index, "6", randomDoc());

        executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);

        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(6, noOfSigmaRuleMatches);

        AtomicBoolean success = new AtomicBoolean(true);
        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        // Call GetAlerts API
                        Map <String, String> alertParams = new HashMap<>();
                        alertParams.put("detector_id", detectorId);
                        alertParams.put("startTime", String.valueOf(startTime.toEpochMilli()));
                        alertParams.put("endTime", String.valueOf(endTime.toEpochMilli()));
                        Response currGetAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, alertParams, null);
                        Map<String, Object> currGetAlertsBody = asMap(currGetAlertsResponse);
                        // TODO enable asserts here when able
                        success.set(Integer.parseInt(currGetAlertsBody.get("total_alerts").toString()) == 2);
                    } catch (IOException ex) {
                        success.set(false);
                    }
                    return success.get();
                }, 2, TimeUnit.MINUTES
        );
        Assert.assertTrue(success.get());
    }

    public void testGetAlerts_noDetector_failure() throws IOException {
        // Call GetAlerts API
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", "nonexistent_detector_id");
        try {
            makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_NOT_FOUND, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    @SuppressWarnings("unchecked")
    public void testAckAlerts_WithInvalidDetectorAlertsCombination() throws IOException {
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

        createAlertingMonitorConfigIndex(null);
        Action triggerAction = randomAction(createDestination());

        Detector detector = randomDetectorWithInputsAndTriggers(List.of(new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(),
                        getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(), List.of(), List.of("attack.defense_evasion"), List.of(triggerAction), List.of())));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        Detector detector1 = randomDetectorWithInputsAndTriggers(List.of(new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(),
                        getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(), List.of(), List.of("attack.defense_evasion"), List.of(triggerAction), List.of())));

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

        // client().performRequest(new Request("POST", "_refresh"));

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
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex(randomDetectorType()), request);
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

    public void testAckAlertsWithInvalidDetector() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

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

        createAlertingMonitorConfigIndex(null);
        Action triggerAction = randomAction(createDestination());

        Detector detector = randomDetectorWithInputsAndTriggers(List.of(new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(createdId)),
                        getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(createdId), List.of(), List.of("attack.defense_evasion"), List.of(triggerAction), List.of())));

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
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex(randomDetectorType()), request);
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
        String body = String.format(Locale.getDefault(), "{\"alerts\":[\"%s\"]}", alertId);
        Request post = new Request("POST", String.format(
                Locale.getDefault(),
                "%s/%s/_acknowledge/alerts",
                SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
                java.util.UUID.randomUUID()));
        post.setJsonEntity(body);

        try {
            client().performRequest(post);
        } catch (ResponseException ex) {
            Assert.assertEquals(HttpStatus.SC_NOT_FOUND, ex.getResponse().getStatusLine().getStatusCode());
        }

        body = String.format(Locale.getDefault(), "{\"alerts\":[\"%s\"]}", java.util.UUID.randomUUID());
        post = new Request("POST", String.format(
                Locale.getDefault(),
                "%s/%s/_acknowledge/alerts",
                SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
                detectorId));
        post.setJsonEntity(body);
    }

    public void testGetAlerts_byDetectorType_success() throws IOException, InterruptedException {
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

        // client().performRequest(new Request("POST", "_refresh"));

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
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex(randomDetectorType()), request);
        }

        // Call GetAlerts API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", randomDetectorType());
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
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
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
        Assert.assertEquals(3, noOfSigmaRuleMatches);

        // execute monitor 2
        executeResponse = executeAlertingMonitor(monitorId2, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        // client().performRequest(new Request("POST", "_refresh"));

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = new ArrayList<>();

        while (hits.size() == 0) {
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex(randomDetectorType()), request);
        }
        hits = new ArrayList<>();
        while (hits.size() == 0) {
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex("network"), request);
        }

        // client().performRequest(new Request("POST", "_refresh"));

        // Call GetAlerts API for WINDOWS detector
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", randomDetectorType());
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        Assert.assertEquals(1, getAlertsBody.get("total_alerts"));
        // Call GetAlerts API for NETWORK detector
        params = new HashMap<>();
        params.put("detectorType", "network");
        getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        getAlertsBody = asMap(getAlertsResponse);
        Assert.assertEquals(1, getAlertsBody.get("total_alerts"));
    }


    @Ignore
    public void testAlertHistoryRollover_maxAge() throws IOException, InterruptedException {
        updateClusterSetting(ALERT_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(ALERT_HISTORY_MAX_DOCS.getKey(), "1000");
        updateClusterSetting(ALERT_HISTORY_INDEX_MAX_AGE.getKey(), "1s");

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

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = new ArrayList<>();

        while (hits.size() == 0) {
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex(randomDetectorType()), request);
        }

        List<String> alertIndices = getAlertIndices(detector.getDetectorType());
        while(alertIndices.size() < 3) {
            alertIndices = getAlertIndices(detector.getDetectorType());
            Thread.sleep(1000);
        }
        assertTrue("Did not find 3 alert indices", alertIndices.size() >= 3);

        restoreAlertsFindingsIMSettings();
    }
    /**
     * 1. Creates detector with aggregation and prepackaged rules
     * (sum rule - should match docIds: 1, 2, 3; maxRule - 4, 5, 6, 7; minRule - 7)
     * 2. Verifies monitor execution
     * 3. Verifies alerts
     *
     * @throws IOException
     */
    public void testMultipleAggregationAndDocRules_alertSuccess() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());

        String infoOpCode = "Info";

        String sumRuleId = createRule(randomAggregationRule("sum", " > 1", infoOpCode));


        List<DetectorRule> detectorRules = List.of(new DetectorRule(sumRuleId));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                Collections.emptyList());
        Detector detector = randomDetectorWithInputsAndTriggers(List.of(input),
                List.of(new DetectorTrigger("randomtrigegr", "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of(), List.of()))
        );

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));


        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()) + "*", request, true);

        assertEquals(1, response.getHits().getTotalHits().value); // 5 for rules, 1 for match_all query in chained findings monitor

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
        Map<String, List> updatedDetectorMap = (HashMap<String, List>) (hit.getSourceAsMap().get("detector"));

        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        indexDoc(index, "1", randomDoc(2, 4, infoOpCode));
        indexDoc(index, "2", randomDoc(3, 4, infoOpCode));

        Map<String, Integer> numberOfMonitorTypes = new HashMap<>();

        for (String monitorId : monitorIds) {
            Map<String, String> monitor = (Map<String, String>) (entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
            numberOfMonitorTypes.merge(monitor.get("monitor_type"), 1, Integer::sum);
            Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());

            // Assert monitor executions
            Map<String, Object> executeResults = entityAsMap(executeResponse);
            if (Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue().equals(monitor.get("monitor_type")) && false == monitor.get("name").equals(detector.getName() + "_chained_findings")) {
                int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
                assertEquals(5, noOfSigmaRuleMatches);
            }
        }

        assertEquals(1, numberOfMonitorTypes.get(Monitor.MonitorType.BUCKET_LEVEL_MONITOR.getValue()).intValue());
        assertEquals(1, numberOfMonitorTypes.get(Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue()).intValue());

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);
        assertEquals(1, getFindingsBody.get("total_findings"));

        String findingDetectorId = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);

        List<String> docLevelFinding = new ArrayList<>();
        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");


        for (Map<String, Object> finding : findings) {
            List<Map<String, Object>> queries = (List<Map<String, Object>>) finding.get("queries");
            Set<String> findingRuleIds = queries.stream().map(it -> it.get("id").toString()).collect(Collectors.toSet());

            // In the case of bucket level monitors, queries will always contain one value
            String aggRuleId = findingRuleIds.iterator().next();
            List<String> findingDocs = (List<String>) finding.get("related_doc_ids");

            if (aggRuleId.equals(sumRuleId)) {
                assertTrue(List.of("1", "2", "3", "4", "5", "6", "7").containsAll(findingDocs));
            }
        }

        assertTrue(Arrays.asList("1", "2", "3", "4", "5", "6", "7", "8").containsAll(docLevelFinding));

        Map<String, String> params1 = new HashMap<>();
        params1.put("detector_id", detectorId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params1, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        // TODO enable asserts here when able
        Assert.assertEquals(3, getAlertsBody.get("total_alerts")); // 2 doc level alerts for each doc, 1 bucket level alert

        input = new DetectorInput("updated", List.of("windows"), detectorRules,
                Collections.emptyList());
        Detector updatedDetector = randomDetectorWithInputsAndTriggers(List.of(input),
                List.of(new DetectorTrigger("updated", "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of(), List.of()))
        );
        /** update detector and verify chained findings monitor should still exist*/
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        updatedDetectorMap = (HashMap<String, List>) (hit.getSourceAsMap().get("detector"));

        assertEquals(2, ((List<String>) (updatedDetectorMap).get("monitor_id")).size());
        indexDoc(index, "3", randomDoc(2, 5, infoOpCode));
        indexDoc(index, "4", randomDoc(3, 5, infoOpCode));

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        updatedDetectorMap = (HashMap<String, List>) (hit.getSourceAsMap().get("detector"));

        monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));
        numberOfMonitorTypes = new HashMap<>();
        for (String monitorId : monitorIds) {
            Map<String, String> monitor = (Map<String, String>) (entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
            numberOfMonitorTypes.merge(monitor.get("monitor_type"), 1, Integer::sum);
            Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());

            // Assert monitor executions
            Map<String, Object> executeResults = entityAsMap(executeResponse);

            if (Monitor.MonitorType.BUCKET_LEVEL_MONITOR.getValue().equals(monitor.get("monitor_type"))) {
                ArrayList triggerResults = new ArrayList(((Map<String, Object>) executeResults.get("trigger_results")).values());
                assertEquals(triggerResults.size(), 1);
                Map<String, Object> triggerResult = (Map<String, Object>) triggerResults.get(0);
                assertTrue(triggerResult.containsKey("agg_result_buckets"));
                HashMap<String, Object> aggResultBuckets = (HashMap<String, Object>) triggerResult.get("agg_result_buckets");
                assertTrue(aggResultBuckets.containsKey("4"));
                assertTrue(aggResultBuckets.containsKey("5"));
            }
        }

        assertEquals(1, numberOfMonitorTypes.get(Monitor.MonitorType.BUCKET_LEVEL_MONITOR.getValue()).intValue());
        assertEquals(1, numberOfMonitorTypes.get(Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue()).intValue());
    }

    @Ignore
    public void testAlertHistoryRollover_maxAge_low_retention() throws IOException, InterruptedException {
        updateClusterSetting(ALERT_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(ALERT_HISTORY_MAX_DOCS.getKey(), "1000");
        updateClusterSetting(ALERT_HISTORY_INDEX_MAX_AGE.getKey(), "1s");

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

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = new ArrayList<>();

        while (hits.size() == 0) {
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex(randomDetectorType()), request);
        }

        List<String> alertIndices = getAlertIndices(detector.getDetectorType());
        while(alertIndices.size() < 3) {
            alertIndices = getAlertIndices(detector.getDetectorType());
            Thread.sleep(1000);
        }
        assertTrue("Did not find 3 alert indices", alertIndices.size() >= 3);

        updateClusterSetting(ALERT_HISTORY_INDEX_MAX_AGE.getKey(), "1000s");
        updateClusterSetting(ALERT_HISTORY_RETENTION_PERIOD.getKey(), "1s");

        while(alertIndices.size() != 1) {
            alertIndices = getAlertIndices(detector.getDetectorType());
            Thread.sleep(1000);
        }

        assertTrue("Did not find 3 alert indices", alertIndices.size() == 1);

        restoreAlertsFindingsIMSettings();
    }

    @Ignore
    public void testAlertHistoryRollover_maxDocs() throws IOException, InterruptedException {
        updateClusterSetting(ALERT_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(ALERT_HISTORY_MAX_DOCS.getKey(), "1");

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

        // client().performRequest(new Request("POST", "_refresh"));

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
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex(randomDetectorType()), request);
        }

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        // TODO enable asserts here when able
        Assert.assertEquals(1, getAlertsBody.get("total_alerts"));
        String alertId = (String) ((ArrayList<HashMap<String, Object>>) getAlertsBody.get("alerts")).get(0).get("id");
        String _detectorId = (String) ((ArrayList<HashMap<String, Object>>) getAlertsBody.get("alerts")).get(0).get("detector_id");

        // Ack alert to move it to history index
        acknowledgeAlert(alertId, detectorId);

        List<String> alertIndices = getAlertIndices(detector.getDetectorType());
        while(alertIndices.size() < 3) {
            alertIndices = getAlertIndices(detector.getDetectorType());
            Thread.sleep(1000);
        }
        assertTrue("Did not find 3 alert indices", alertIndices.size() >= 3);

        restoreAlertsFindingsIMSettings();
    }

    public void testGetAlertsFromAllIndices() throws IOException, InterruptedException {
        updateClusterSetting(ALERT_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(ALERT_HISTORY_MAX_DOCS.getKey(), "1");

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

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = new ArrayList<>();

        while (hits.size() == 0) {
            hits = executeSearch(DetectorMonitorConfig.getAlertsIndex(randomDetectorType()), request);
        }

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
        // TODO enable asserts here when able
        Assert.assertEquals(1, getAlertsBody.get("total_alerts"));
        String alertId = (String) ((ArrayList<HashMap<String, Object>>) getAlertsBody.get("alerts")).get(0).get("id");
        String _detectorId = (String) ((ArrayList<HashMap<String, Object>>) getAlertsBody.get("alerts")).get(0).get("detector_id");

        // Ack alert to move it to history index
        acknowledgeAlert(alertId, detectorId);

        List<String> alertIndices = getAlertIndices(detector.getDetectorType());
        // alertIndex + 2 alertHistory indices
        while(alertIndices.size() < 3) {
            alertIndices = getAlertIndices(detector.getDetectorType());
            Thread.sleep(1000);
        }
        assertTrue("Did not find 3 alert indices", alertIndices.size() >= 3);

        // Index another doc to generate new alert in alertIndex
        indexDoc(index, "2", randomDoc());

        executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);

        client().performRequest(new Request("POST", DetectorMonitorConfig.getAlertsIndex(randomDetectorType()) + "/_refresh"));

        getAlertsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
        getAlertsBody = asMap(getAlertsResponse);
        // 1 from alertIndex and 1 from history index
        Assert.assertEquals(2, getAlertsBody.get("total_alerts"));

        restoreAlertsFindingsIMSettings();
    }
}