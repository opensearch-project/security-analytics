/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.findings;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.commons.alerting.model.Monitor.MonitorType;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Detector.DetectorType;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;

import static org.opensearch.securityanalytics.TestHelpers.netFlowMappings;
import static org.opensearch.securityanalytics.TestHelpers.randomAggregationRule;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.randomRule;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;
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

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));

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

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));

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
        params.put("detectorType", detector.getDetectorTypes().get(0));
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
    }

    public void testGetFindings_byDetectorType_oneDetector_multipleDetectorTypes_success() throws IOException {
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

        createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + "windows" + "\", " +
                "  \"partial\":true" +
                "}"
        );

        response = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Fetching 10 rules -> 5 from test_windows and 5 from windows category
        List<String> prepackagedRules = getRandomPrePackagedRules();
        String randomDocRuleId = createRule(randomRule(), "windows");

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(randomDocRuleId)),
            prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()), List.of(DetectorType.TEST_WINDOWS, DetectorType.WINDOWS));

        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

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

        Map<String, List> detectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = detectorMap.get("inputs");

        assertEquals("Number of custom rules not correct", 1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));

        assertEquals("Number of monitors not correct", 2, monitorIds.size());

        Map<String, String> docLevelMonitorIdPerCategory = ((Map<String, String>)((Map<String, Object>)hit.getSourceAsMap().get("detector")).get("doc_monitor_id_per_category"));
        // Swapping keys and values
        Map<String, String> ruleIdRuleCategoryMap =  docLevelMonitorIdPerCategory.entrySet().stream().collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));

        String infoOpCode = "Info";
        String testOpCode = "Test";
        indexDoc(index, "1", randomDoc(2, 4, infoOpCode));
        indexDoc(index, "2", randomDoc(3, 4, infoOpCode));
        indexDoc(index, "3", randomDoc(1, 4, infoOpCode));
        indexDoc(index, "4", randomDoc(5, 3, testOpCode));
        indexDoc(index, "5", randomDoc(2, 3, testOpCode));
        indexDoc(index, "6", randomDoc(4, 3, testOpCode));
        indexDoc(index, "7", randomDoc(6, 2, testOpCode));
        indexDoc(index, "8", randomDoc(1, 1, testOpCode));

        Set<String> expectedDocIds = Set.of("1", "2", "3", "4", "5", "6", "7", "8");

        for(String monitorId: monitorIds) {
            Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
            Map<String, Object> executeResults = entityAsMap(executeResponse);

            String ruleCategory = ruleIdRuleCategoryMap.get(monitorId);
            int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();

            if (ruleCategory.toLowerCase(Locale.ROOT).equals(DetectorType.WINDOWS.getDetectorType().toLowerCase(Locale.ROOT))) {
                Assert.assertEquals(1, noOfSigmaRuleMatches);
                // Call GetFindings API
                Map<String, String> params = new HashMap<>();
                params.put("detectorType", DetectorType.WINDOWS.getDetectorType());
                Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
                Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

                assertEquals("Number of total findings for windows category not correct", 8, getFindingsBody.get("total_findings"));
                assertFindingsPerExecutedDocLevelMonitor(getFindingsBody, expectedDocIds);

            } else {
                assertEquals("Number of doc level rules for test_windows category not correct", 5, noOfSigmaRuleMatches);
                // Call GetFindings API
                Map<String, String> params = new HashMap<>();
                params.put("detectorType", DetectorType.TEST_WINDOWS.getDetectorType());
                Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
                Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

                assertEquals("Number of total findings for test_windows category not correct", 8, getFindingsBody.get("total_findings"));
                assertFindingsPerExecutedDocLevelMonitor(getFindingsBody, expectedDocIds);
            }
        }
    }
    public void testGetFindings_byDetectorType_multipleDetectorTypes_FindingForOneLogType_success() throws IOException {
        String infoOpCode = "Info";
        String testOpCode = "Test";
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

        createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + "windows" + "\", " +
                "  \"partial\":true" +
                "}"
        );

        response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Fetching 6 rules -> 5 from test_windows and 1 from windows category (custom doc rule)
        List<String> prepackagedRules = getRandomPrePackagedRules();
        String maxRuleId = createRule(randomAggregationRule("max", " > 3", testOpCode));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(maxRuleId)),
            prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()), List.of(DetectorType.TEST_WINDOWS, DetectorType.WINDOWS));

        Detector detector = randomDetectorWithInputs(List.of(input));
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

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

        Map<String, List> detectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = detectorMap.get("inputs");
        assertEquals("Number of custom rules not correct", 1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());
        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        // 2 doc level monitors - one per each category: test_windows and windows
        // 1 bucket level monitor - for windows category
        assertEquals("Number of monitors not correct", 2, monitorIds.size());

        Map<String, String> docLevelMonitorIdPerCategory = ((Map<String, String>)((Map<String, Object>)hit.getSourceAsMap().get("detector")).get("doc_monitor_id_per_category"));
        // Swapping keys and values
        Map<String, String> ruleIdRuleCategoryMap =  docLevelMonitorIdPerCategory.entrySet().stream().collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));


        indexDoc(index, "1", randomDoc(2, 4, infoOpCode));
        indexDoc(index, "2", randomDoc(3, 4, infoOpCode));
        indexDoc(index, "3", randomDoc(1, 4, infoOpCode));
        indexDoc(index, "4", randomDoc(2, 3, testOpCode));
        indexDoc(index, "5", randomDoc(2, 3, testOpCode));
        indexDoc(index, "6", randomDoc(1, 3, testOpCode));
        indexDoc(index, "7", randomDoc(1, 2, testOpCode));
        indexDoc(index, "8", randomDoc(1, 1, testOpCode));
        Set<String> expectedDocIds = Set.of("1", "2", "3", "4", "5", "6", "7", "8");

        Map<String, Integer> numberOfMonitorTypes = new HashMap<>();

        for(String monitorId: monitorIds) {
            Map<String, String> monitor  = (Map<String, String>)(entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
            numberOfMonitorTypes.merge(monitor.get("monitor_type"), 1, Integer::sum);
            Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
            Map<String, Object> executeResults = entityAsMap(executeResponse);

            if (MonitorType.DOC_LEVEL_MONITOR.getValue().equals(monitor.get("monitor_type"))) {
                int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
                assertEquals("Number of doc level rules not correct", 5, noOfSigmaRuleMatches);

                // Call GetFindings API
                Map<String, String> params = new HashMap<>();
                params.put("detectorType", DetectorType.TEST_WINDOWS.getDetectorType());
                Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
                Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

                assertEquals("Number of total findings for test_windows category not correct", 8, getFindingsBody.get("total_findings"));
                assertFindingsPerExecutedDocLevelMonitor(getFindingsBody, expectedDocIds);
            } else {
                List<Map<String, Object>> buckets = ((List<Map<String, Object>>)(((Map<String, Object>)((Map<String, Object>)((Map<String, Object>)((List<Object>)((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0)).get("aggregations")).get("result_agg")).get("buckets")));
                Integer docCount = buckets.stream().mapToInt(it -> (Integer)it.get("doc_count")).sum();
                assertEquals("Number of bucket level monitors not correct", 5, docCount.intValue());
                List<String> triggerResultBucketKeys = ((Map<String, Object>)((Map<String, Object>) ((Map<String, Object>)executeResults.get("trigger_results")).get(maxRuleId)).get("agg_result_buckets")).keySet().stream().collect(Collectors.toList());
                assertEquals(Collections.emptyList(), triggerResultBucketKeys);

                // Call GetFindings API
                Map<String, String> params = new HashMap<>();
                params.put("detectorType", DetectorType.WINDOWS.getDetectorType());
                Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
                Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
                assertEquals("Number of total findings for windows category not correct", 0, getFindingsBody.get("total_findings"));
            }
        }
        assertEquals("Number of bucket level monitors not correct", 1, numberOfMonitorTypes.get(MonitorType.BUCKET_LEVEL_MONITOR.getValue()).intValue());
        assertEquals("Number of doc level monitors not correct", 1, numberOfMonitorTypes.get(MonitorType.DOC_LEVEL_MONITOR.getValue()).intValue());
    }

    public void testGetFindings_byDetectorId_oneDetector_multipleDetectorTypes_success() throws IOException {
        String infoOpCode = "Info";
        String testOpCode = "Test";
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

        createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
            "{ \"index_name\":\"" + index + "\"," +
                "  \"rule_topic\":\"" + "windows" + "\", " +
                "  \"partial\":true" +
                "}"
        );

        response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Fetching 6 rules -> 5 from test_windows and 1 from windows category (custom doc rule)
        List<String> prepackagedRules = getRandomPrePackagedRules();
        String randomDocRuleId = createRule(randomRule(), "windows");
        String maxRuleId = createRule(randomAggregationRule("max", " > 3", testOpCode));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(randomDocRuleId), new DetectorRule(maxRuleId)),
            prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()), List.of(DetectorType.TEST_WINDOWS, DetectorType.WINDOWS));

        Detector detector = randomDetectorWithInputs(List.of(input));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

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

        Map<String, List> detectorMap = (HashMap<String,List>)(hit.getSourceAsMap().get("detector"));
        List inputArr = detectorMap.get("inputs");
        assertEquals("Number of custom rules not correct",  2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());
        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        // 2 doc level monitors - one per each category: test_windows and windows
        // 1 bucket level monitor - for windows category
        assertEquals("Number of monitors not correct", 3, monitorIds.size());

        Map<String, String> docLevelMonitorIdPerCategory = ((Map<String, String>)((Map<String, Object>)hit.getSourceAsMap().get("detector")).get("doc_monitor_id_per_category"));
        // Swapping keys and values
        Map<String, String> ruleIdRuleCategoryMap =  docLevelMonitorIdPerCategory.entrySet().stream().collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));


        indexDoc(index, "1", randomDoc(2, 4, infoOpCode));
        indexDoc(index, "2", randomDoc(3, 4, infoOpCode));
        indexDoc(index, "3", randomDoc(1, 4, infoOpCode));
        indexDoc(index, "4", randomDoc(5, 3, testOpCode));
        indexDoc(index, "5", randomDoc(2, 3, testOpCode));
        indexDoc(index, "6", randomDoc(4, 3, testOpCode));
        indexDoc(index, "7", randomDoc(6, 2, testOpCode));
        indexDoc(index, "8", randomDoc(1, 1, testOpCode));

        Map<String, Integer> numberOfMonitorTypes = new HashMap<>();

        for(String monitorId: monitorIds) {
            Map<String, String> monitor  = (Map<String, String>)(entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
            numberOfMonitorTypes.merge(monitor.get("monitor_type"), 1, Integer::sum);
            Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
            Map<String, Object> executeResults = entityAsMap(executeResponse);

            if (MonitorType.DOC_LEVEL_MONITOR.getValue().equals(monitor.get("monitor_type"))) {
                String ruleCategory = ruleIdRuleCategoryMap.get(monitorId);
                int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
                if (ruleCategory.toLowerCase(Locale.ROOT).equals(DetectorType.WINDOWS.getDetectorType().toLowerCase(Locale.ROOT))) {
                    assertEquals("Number of doc level rules for windows category not correct", 1, noOfSigmaRuleMatches);
                } else if(ruleCategory.toLowerCase(Locale.ROOT).equals(DetectorType.TEST_WINDOWS.getDetectorType().toLowerCase(Locale.ROOT))){
                    assertEquals("Number of doc level rules for test_windows category not correct", 5, noOfSigmaRuleMatches);
                }
            } else {
                List<Map<String, Object>> buckets = ((List<Map<String, Object>>)(((Map<String, Object>)((Map<String, Object>)((Map<String, Object>)((List<Object>)((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0)).get("aggregations")).get("result_agg")).get("buckets")));
                Integer docCount = buckets.stream().mapToInt(it -> (Integer)it.get("doc_count")).sum();
                assertEquals("Number of documents in buckets not correct", 5, docCount.intValue());
                List<String> triggerResultBucketKeys = ((Map<String, Object>)((Map<String, Object>) ((Map<String, Object>)executeResults.get("trigger_results")).get(maxRuleId)).get("agg_result_buckets")).keySet().stream().collect(Collectors.toList());
                assertEquals("Trigger result not correct", List.of("2", "3"), triggerResultBucketKeys);
            }
        }

        assertEquals("Number of bucket level monitors not correct", 1, numberOfMonitorTypes.get(MonitorType.BUCKET_LEVEL_MONITOR.getValue()).intValue());
        assertEquals("Number of doc level monitors not correct", 2, numberOfMonitorTypes.get(MonitorType.DOC_LEVEL_MONITOR.getValue()).intValue());

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        // 8 findings from prepackaged doc rules
        // 8 findings from custom created doc level rule
        // 1 finding from custom aggregation rule
        assertEquals("Number of total findings not correct", 17, getFindingsBody.get("total_findings"));
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
        Detector detector1 = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));
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
                getPrePackagedRules("network").stream().map(DetectorRule::new).collect(Collectors.toList()), List.of(Detector.DetectorType.NETWORK));
        Detector detector2 = randomDetectorWithTriggers(
                getPrePackagedRules("network"),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("network"), List.of(), List.of(), List.of(), List.of())),
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
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        client().performRequest(new Request("POST", "_refresh"));

        // Call GetFindings API for first detector
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", detector1.getDetectorTypes().get(0));
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
        // Call GetFindings API for second detector
        params.clear();
        params.put("detectorType", detector2.getDetectorTypes().get(0));
        getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
    }


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

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));

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

        List<String> findingIndices = getFindingIndices(detector.getDetectorTypes().get(0));
        while(findingIndices.size() < 2) {
            findingIndices = getFindingIndices(detector.getDetectorTypes().get(0));
            Thread.sleep(1000);
        }
        assertTrue("Did not find 3 alert indices", findingIndices.size() >= 2);
    }

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

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));

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

        List<String> findingIndices = getFindingIndices(detector.getDetectorTypes().get(0));
        while(findingIndices.size() < 2) {
            findingIndices = getFindingIndices(detector.getDetectorTypes().get(0));
            Thread.sleep(1000);
        }
        assertTrue("Did not find 3 alert indices", findingIndices.size() >= 2);
    }

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

        Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));

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
        client().performRequest(new Request("POST", "_refresh"));
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));

        List<String> findingIndices = getFindingIndices(detector.getDetectorTypes().get(0));
        while(findingIndices.size() < 2) {
            findingIndices = getFindingIndices(detector.getDetectorTypes().get(0));
            Thread.sleep(1000);
        }
        assertTrue("Did not find 3 findings indices", findingIndices.size() >= 2);

        updateClusterSetting(FINDING_HISTORY_RETENTION_PERIOD.getKey(), "1s");
        updateClusterSetting(FINDING_HISTORY_MAX_DOCS.getKey(), "1000");
        while(findingIndices.size() != 1) {
            findingIndices = getFindingIndices(detector.getDetectorTypes().get(0));
            Thread.sleep(1000);
        }

        assertTrue("Found finding indices but expected none", findingIndices.size() == 1);

        // Exec monitor again to make sure that current
        indexDoc(index, "2", randomDoc());

        executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);

        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
        client().performRequest(new Request("POST", "_refresh"));
        getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        getFindingsBody = entityAsMap(getFindingsResponse);
        Assert.assertEquals(1, getFindingsBody.get("total_findings"));
    }

    private static void assertFindingsPerExecutedDocLevelMonitor(Map<String, Object> getFindingsBody, Set<String> expectedDocIds) {
        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");
        List<String> relatedDocFinding = new ArrayList<>();
        for(Map<String, Object> finding : findings) {
            relatedDocFinding.addAll((List<String>) finding.get("related_doc_ids"));
        }
        assertTrue(expectedDocIds.containsAll(relatedDocFinding));
    }
}
