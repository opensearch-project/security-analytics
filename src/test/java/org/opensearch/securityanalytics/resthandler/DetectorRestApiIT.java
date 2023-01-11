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
import org.opensearch.common.Strings;
import org.opensearch.common.settings.Settings;
import org.opensearch.client.ResponseException;
import org.opensearch.common.xcontent.XContentFactory;
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

import static org.opensearch.securityanalytics.TestHelpers.*;

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

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", randomDetectorType().toLowerCase(Locale.ROOT), detectorTypeInResponse);

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

    public void testCreatingADetectorWithIndexNotExists() throws IOException {
        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));

        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        } catch (ResponseException ex) {
            Assert.assertEquals(404, ex.getResponse().getStatusLine().getStatusCode());
        }
    }

    public void testCreatingADetectorWithNonExistingCustomRule() throws IOException {
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
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(java.util.UUID.randomUUID().toString())),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        } catch (ResponseException ex) {
            Assert.assertEquals(404, ex.getResponse().getStatusLine().getStatusCode());
        }
    }

    /**
     * 1. Creates detector with no rules
     * 2. Detector without rules and monitors created successfully
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

        // Verify rules
        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()) + "*", request, true);
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

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", randomDetectorType().toLowerCase(Locale.ROOT), detectorTypeInResponse);
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

        List<Map<String, Object>> hits = ((List<Map<String, Object>>) ((Map<String, Object>) searchResponseBody.get("hits")).get("hits"));
        Map<String, Object> hit = hits.get(0);
        String detectorTypeInResponse = (String)  ((Map<String, Object>) hit.get("_source")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", detectorTypeInResponse, randomDetectorType().toLowerCase(Locale.ROOT));
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

        String detectorType = (String)  ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", detectorType, randomDetectorType().toLowerCase(Locale.ROOT));

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
                        "  \"rule_topic\":\"test_windows\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String customAvgRuleId = createRule(productIndexAvgAggRule());

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(customAvgRuleId)),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();
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
        // Verify if the rule id in bucket level finding is the same as rule used for bucket monitor creation
        assertEquals(customAvgRuleId, ruleId);
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

        String detectorTypeInResponse = (String) ((Map<String, Object>) (asMap(updateResponse).get("detector"))).get("detector_type");
        Assert.assertEquals("Detector type incorrect", randomDetectorType().toLowerCase(Locale.ROOT), detectorTypeInResponse);

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);
        Assert.assertEquals(6, response.getHits().getTotalHits().value);
    }

    public void testUpdateANonExistingDetector() throws IOException {
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

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector updatedDetector = randomDetectorWithInputs(List.of(input));

        try {
            makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + java.util.UUID.randomUUID(), Collections.emptyMap(), toHttpEntity(updatedDetector));
        } catch (ResponseException ex) {
            Assert.assertEquals(404, ex.getResponse().getStatusLine().getStatusCode());
        }
    }

    public void testUpdateADetectorWithIndexNotExists() throws IOException {
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector updatedDetector = randomDetectorWithInputs(List.of(input));

        try {
            makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + java.util.UUID.randomUUID(), Collections.emptyMap(), toHttpEntity(updatedDetector));
        } catch (ResponseException ex) {
            Assert.assertEquals(404, ex.getResponse().getStatusLine().getStatusCode());
        }
    }

    @SuppressWarnings("unchecked")
    public void testDeletingADetector_single_ruleTopicIndex() throws IOException {
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
        // Create detector #1 of type test_windows
        Detector detector1 = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));
        String detectorId1 = createDetector(detector1);

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId1 + "\"\n" +
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
        // Create detector #2 of type windows
        Detector detector2 = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));
        String detectorId2 = createDetector(detector2);

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId2 + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);

        monitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index, "2", randomDoc());

        executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);

        Response deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId1, Collections.emptyMap(), null);
        Assert.assertEquals("Delete detector failed", RestStatus.OK, restStatus(deleteResponse));
        // We deleted 1 detector, but 1 detector with same type exists, so we expect queryIndex to be present
        Assert.assertTrue(doesIndexExist(String.format(Locale.getDefault(), ".opensearch-sap-%s-detectors-queries-000001", "test_windows")));

        deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId2, Collections.emptyMap(), null);
        Assert.assertEquals("Delete detector failed", RestStatus.OK, restStatus(deleteResponse));
        // We deleted all detectors of type windows, so we expect that queryIndex is deleted
        Assert.assertFalse(doesIndexExist(String.format(Locale.getDefault(), ".opensearch-sap-%s-detectors-queries-000001", "test_windows")));

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId1 + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        Assert.assertEquals(0, hits.size());

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId2 + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        Assert.assertEquals(0, hits.size());
    }

    public void testDeletingADetector_oneDetectorType_multiple_ruleTopicIndex() throws IOException {
        String index1 = "test_index_1";
        createIndex(index1, Settings.EMPTY);
        String index2 = "test_index_2";
        createIndex(index2, Settings.EMPTY);
        // Insert doc with 900 fields to update mappings too
        String doc = createDocumentWithNFields(900);
        indexDoc(index1, "1", doc);
        indexDoc(index2, "1", doc);

        // Create detector #1 of type test_windows
        Detector detector1 = randomDetectorWithTriggers(
                getRandomPrePackagedRules(),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())),
                List.of(index1)
        );
        String detectorId1 = createDetector(detector1);

        // Create detector #2 of type test_windows
        Detector detector2 = randomDetectorWithTriggers(
                getRandomPrePackagedRules(),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())),
                List.of(index2)
        );

        String detectorId2 = createDetector(detector2);

        Assert.assertTrue(doesIndexExist(".opensearch-sap-test_windows-detectors-queries-000001"));
        Assert.assertTrue(doesIndexExist(".opensearch-sap-test_windows-detectors-queries-000002"));

        // Check if both query indices have proper settings applied from index template
        Map<String, Object> settings = getIndexSettingsAsMap(".opensearch-sap-test_windows-detectors-queries-000001");
        assertTrue(settings.containsKey("index.analysis.char_filter.rule_ws_filter.pattern"));
        assertTrue(settings.containsKey("index.hidden"));
        settings = getIndexSettingsAsMap(".opensearch-sap-test_windows-detectors-queries-000002");
        assertTrue(settings.containsKey("index.analysis.char_filter.rule_ws_filter.pattern"));
        assertTrue(settings.containsKey("index.hidden"));

        Response deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId1, Collections.emptyMap(), null);
        Assert.assertEquals("Delete detector failed", RestStatus.OK, restStatus(deleteResponse));
        // We deleted 1 detector, but 1 detector with same type exists, so we expect queryIndex to be present
        Assert.assertFalse(doesIndexExist(String.format(Locale.getDefault(), ".opensearch-sap-%s-detectors-queries-000001", "test_windows")));
        Assert.assertTrue(doesIndexExist(String.format(Locale.getDefault(), ".opensearch-sap-%s-detectors-queries-000002", "test_windows")));

        deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId2, Collections.emptyMap(), null);
        Assert.assertEquals("Delete detector failed", RestStatus.OK, restStatus(deleteResponse));
        // We deleted all detectors of type windows, so we expect that queryIndex is deleted
        Assert.assertFalse(doesIndexExist(String.format(Locale.getDefault(), ".opensearch-sap-%s-detectors-queries-000001", "test_windows")));
        Assert.assertFalse(doesIndexExist(String.format(Locale.getDefault(), ".opensearch-sap-%s-detectors-queries-000002", "test_windows")));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId1 + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        Assert.assertEquals(0, hits.size());

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId2 + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        Assert.assertEquals(0, hits.size());
    }

    public void testDeletingANonExistingDetector() throws IOException {
        try {
            makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + java.util.UUID.randomUUID(), Collections.emptyMap(), null);
        } catch (ResponseException ex) {
            Assert.assertEquals(404, ex.getResponse().getStatusLine().getStatusCode());
        }
    }

    public void testCreatingADetectorWithTimestampFieldAliasMapping() throws IOException {
        String index = createTestIndex(randomIndex(), productIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"test_windows\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Request updateRequest = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        updateRequest.setJsonEntity(Strings.toString(XContentFactory.jsonBuilder().map(Map.of(
                "index_name", index,
                "field", "time",
                "alias", "timestamp"))));
        Response apiResponse = client().performRequest(updateRequest);
        assertEquals(HttpStatus.SC_OK, apiResponse.getStatusLine().getStatusCode());

        String customAvgRuleId = createRule(productIndexAvgAggRule());

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(customAvgRuleId)),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();
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

        indexDoc(index, "1", randomProductDocumentWithTime(System.currentTimeMillis()));

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
        // Verify if the rule id in bucket level finding is the same as rule used for bucket monitor creation
        assertEquals(customAvgRuleId, ruleId);
        Response getResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        String getDetectorResponseString = new String(getResponse.getEntity().getContent().readAllBytes());
        Assert.assertTrue(getDetectorResponseString.contains(ruleId));
    }

    public void testCreatingADetectorWithTimestampFieldAliasMapping_verifyTimeRangeInBucketMonitor() throws IOException {
        String index = createTestIndex(randomIndex(), productIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"test_windows\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Request updateRequest = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        updateRequest.setJsonEntity(Strings.toString(XContentFactory.jsonBuilder().map(Map.of(
                "index_name", index,
                "field", "time",
                "alias", "timestamp"))));
        Response apiResponse = client().performRequest(updateRequest);
        assertEquals(HttpStatus.SC_OK, apiResponse.getStatusLine().getStatusCode());

        String customAvgRuleId = createRule(productIndexAvgAggRule());

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(customAvgRuleId)),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String detectorId = responseBody.get("_id").toString();
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

        indexDoc(index, "1", randomProductDocumentWithTime(System.currentTimeMillis()-1000*60*70)); // doc's timestamp is older than 1 hr

        Response executeResponse = executeAlertingMonitor(bucketLevelMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        // verify bucket level monitor findings
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        assertNotNull(getFindingsBody);
        Assert.assertEquals(0, getFindingsBody.get("total_findings"));
        List<?> findings = (List<?>) getFindingsBody.get("findings");
        Assert.assertEquals(findings.size(), 0); //there should be no findings as doc is not in time range of current run
    }
}