/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.entity.ContentType;
import org.apache.http.nio.entity.NStringEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
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

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.model.Rule;

import static org.opensearch.securityanalytics.TestHelpers.productIndexMaxAggRule;
import static org.opensearch.securityanalytics.TestHelpers.productIndexAvgAggRule;
import static org.opensearch.securityanalytics.TestHelpers.productIndexMapping;
import static org.opensearch.securityanalytics.TestHelpers.randomDetector;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.randomProductDocument;
import static org.opensearch.securityanalytics.TestHelpers.randomRule;
import static org.opensearch.securityanalytics.TestHelpers.sumAggregationTestRule;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;

public class DetectorRestApiIT extends SecurityAnalyticsRestTestCase {

    @SuppressWarnings("unchecked")
    public void testCreatingADetector() throws IOException {
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

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

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
    }

    /**
     * 1. Creates detector with no rules
     * 2. Detector without rules and monitors created successfully
     * @throws IOException
     */
    public void testCreateDetectorWithoutRules() throws IOException {
/*        String index = createTestIndex(randomIndex(), windowsIndexMapping());

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
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));*/
    }

    public void testGettingADetector() throws IOException {
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

        Detector detector = randomDetector(getRandomPrePackagedRules());
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create monitor failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> createResponseBody = asMap(createResponse);

        String createdId = createResponseBody.get("_id").toString();

        Response getResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
        Map<String, Object> responseBody = asMap(getResponse);
        Assert.assertEquals(createdId, responseBody.get("_id"));
        Assert.assertNotNull(responseBody.get("detector"));
    }

    @SuppressWarnings("unchecked")
    public void testSearchingDetectors() throws IOException {
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

        Detector detector = randomDetector(getRandomPrePackagedRules());

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create monitor failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> createResponseBody = asMap(createResponse);

        String createdId = createResponseBody.get("_id").toString();

        String queryJson = "{ \"query\": { \"match\": { \"_id\" : \"" + createdId + "\"} } }";
        HttpEntity requestEntity = new NStringEntity(queryJson, ContentType.APPLICATION_JSON);
        Response searchResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + "_search", Collections.emptyMap(), requestEntity);
        Map<String, Object> searchResponseBody = asMap(searchResponse);
        Assert.assertNotNull("response is not null", searchResponseBody);
        Map<String, Object> searchResponseHits = (Map) searchResponseBody.get("hits");
        Map<String, Object> searchResponseTotal = (Map) searchResponseHits.get("total");
        Assert.assertEquals(1, searchResponseTotal.get("value"));
    }

    @SuppressWarnings("unchecked")
    public void testCreatingADetectorWithCustomRules() throws IOException {
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

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(createdId)),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

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
    }

    public void testCreatingADetectorWithAggregationRules() throws IOException {
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

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = productIndexAvgAggRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "windows"),
            new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(detectorId)),
            getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        detectorId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, detectorId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, detectorId), createResponse.getHeader("Location"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

        String request = "{\n" +
            "   \"query\" : {\n" +
            "     \"match\":{\n" +
            "        \"_id\": \"" + detectorId + "\"\n" +
            "     }\n" +
            "   }\n" +
            "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        List<String> monitorTypes = new ArrayList<>();

        Map<String, Object> detectorAsMap = (Map<String, Object>) hit.getSourceAsMap().get("detector");

        String bucketLevelMonitorId = "";

        // Verify that doc level monitor is created
        List<String> monitorIds = (List<String>) (detectorAsMap).get("monitor_id");

        String firstMonitorId = monitorIds.get(0);
        String firstMonitorType  = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + firstMonitorId))).get("monitor")).get("monitor_type");

        if(MonitorType.BUCKET_LEVEL_MONITOR.getValue().equals(firstMonitorType)){
            bucketLevelMonitorId = firstMonitorId;
        }
        monitorTypes.add(firstMonitorType);

        String secondMonitorId = monitorIds.get(1);
        String secondMonitorType  = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + secondMonitorId))).get("monitor")).get("monitor_type");
        monitorTypes.add(secondMonitorType);
        if(MonitorType.BUCKET_LEVEL_MONITOR.getValue().equals(secondMonitorType)){
            bucketLevelMonitorId = secondMonitorId;
        }
        Assert.assertTrue(Arrays.asList(MonitorType.BUCKET_LEVEL_MONITOR.getValue(), MonitorType.DOC_LEVEL_MONITOR.getValue()).containsAll(monitorTypes));

        indexDoc(index, "1", randomProductDocument());

        Response executeResponse = executeAlertingMonitor(bucketLevelMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        // verify bucket level monitor findings
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        assertNotNull(getFindingsBody);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
        List<?> findings = (List<?>) getFindingsBody.get("findings");
        Assert.assertEquals(findings.size(), 1);
        HashMap<String, Object> finding = (HashMap<String, Object>) findings.get(0);
        Assert.assertTrue(finding.containsKey("queries"));
        HashMap<String, Object> docLevelQuery = (HashMap<String, Object>) ((List<?>) finding.get("queries")).get(0);
        String ruleId = docLevelQuery.get("id").toString();
        Response getResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        String getDetectorResponseString = new String(getResponse.getEntity().getContent().readAllBytes());
        Assert.assertTrue(getDetectorResponseString.contains(ruleId));
    }
    public void testUpdateADetector() throws IOException {
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

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(createdId)),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector updatedDetector = randomDetectorWithInputs(List.of(input));

        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));
        Assert.assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);
        Assert.assertEquals(6, response.getHits().getTotalHits().value);
    }

    public void testUpdateDetectorAddingNewAggregationRule() throws IOException {
/*        String index = createTestIndex(randomIndex(), productIndexMapping());

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
        Assert.assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());*/
    }

    public void testUpdateDetectorDeletingExistingAggregationRule() throws IOException {
/*        String index = createTestIndex(randomIndex(), productIndexMapping());

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
        Assert.assertEquals(1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());*/
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

    @SuppressWarnings("unchecked")
    public void testDeletingADetector() throws IOException {
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

        Detector detector = randomDetector(getRandomPrePackagedRules());

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

        Response deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
        Assert.assertEquals("Delete detector failed", RestStatus.OK, restStatus(deleteResponse));

        Assert.assertFalse(alertingMonitorExists(monitorId));

        Assert.assertFalse(doesIndexExist(String.format(Locale.getDefault(), ".opensearch-sap-%s-detectors-queries", "windows")));

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        Assert.assertEquals(0, hits.size());
    }
}