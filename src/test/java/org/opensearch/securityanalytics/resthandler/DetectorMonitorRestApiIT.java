/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
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
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.model.Rule;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;

import static org.opensearch.securityanalytics.TestHelpers.cloudtrailOcsfMappings;
import static org.opensearch.securityanalytics.TestHelpers.randomAggregationRule;
import static org.opensearch.securityanalytics.TestHelpers.randomCloudtrailAggrRule;
import static org.opensearch.securityanalytics.TestHelpers.randomCloudtrailAggrRuleWithDotFields;
import static org.opensearch.securityanalytics.TestHelpers.randomCloudtrailAggrRuleWithEcsFields;
import static org.opensearch.securityanalytics.TestHelpers.randomCloudtrailDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomCloudtrailOcsfDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomDetector;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputsAndTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.randomRule;
import static org.opensearch.securityanalytics.TestHelpers.randomRuleWithKeywords;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;
import static org.opensearch.securityanalytics.TestHelpers.randomRuleWithStringKeywords;
import static org.opensearch.securityanalytics.TestHelpers.randomDocOnlyNumericAndDate;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMappingOnlyNumericAndDate;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMappingOnlyNumericAndText;
import static org.opensearch.securityanalytics.TestHelpers.randomRuleWithDateKeywords;
import static org.opensearch.securityanalytics.TestHelpers.randomDocOnlyNumericAndText;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ENABLE_WORKFLOW_USAGE;

public class DetectorMonitorRestApiIT extends SecurityAnalyticsRestTestCase {
    /**
     * 1. Creates detector with 5 doc prepackaged level rules and one doc level monitor based on the given rules
     * 2. Creates two aggregation rules and assigns to a detector, while removing 5 prepackaged rules
     * 3. Verifies that two bucket level monitor exists
     * 4. Verifies the findings
     *
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
        String monitorType = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");

        assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

        // Create aggregation rules
        String sumRuleId = createRule(randomAggregationRule("sum", " > 2"));
        String avgTermRuleId = createRule(randomAggregationRule("avg", " > 1"));
        // Update detector and empty doc level rules so detector contains only one aggregation rule
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(sumRuleId), new DetectorRule(avgTermRuleId)),
                emptyList());
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
        for (String id : monitorIds) {
            monitorType = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + id))).get("monitor")).get("monitor_type");
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

        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");
        for (Map<String, Object> finding : findings) {
            Set<String> aggRulesFinding = ((List<Map<String, Object>>) finding.get("queries")).stream().map(it -> it.get("id").toString()).collect(
                    Collectors.toSet());
            // Bucket monitor finding will have one rule
            String aggRuleId = aggRulesFinding.iterator().next();

            assertTrue(aggRulesFinding.contains(aggRuleId));

            List<String> findingDocs = (List<String>) finding.get("related_doc_ids");
            Assert.assertEquals(2, findingDocs.size());
            assertTrue(Arrays.asList("1", "2").containsAll(findingDocs));
        }

        String findingDetectorId = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);
    }

    /**
     * 1. Creates detector with 1 aggregation rule and one bucket level monitor based on the aggregation rule
     * 2. Creates 5 prepackaged doc level rules and one custom doc level rule and removes the aggregation rule
     * 3. Verifies that one doc level monitor exists
     * 4. Verifies the findings
     *
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

        String maxRuleId = createRule(randomAggregationRule("max", " > 2"));
        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
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

        String monitorType = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");

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
        monitorType = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");

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
        String monitorType = ((Map<String, String>) entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId))).get("monitor")).get("monitor_type");

        assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

        Detector updatedDetector = randomDetector(emptyList());
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
                emptyList());
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
        Map<String, List> detectorMap = (HashMap<String, List>) (hit.getSourceAsMap().get("detector"));
        List inputArr = detectorMap.get("inputs");

        assertEquals(1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        // Test adding the new max monitor and updating the existing sum monitor
        String maxRuleId = createRule(randomAggregationRule("max", " > 3"));
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(maxRuleId), new DetectorRule(sumRuleId)),
                emptyList());
        Detector updatedDetector = randomDetectorWithInputs(List.of(newInput));
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(updatedDetector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        Map<String, List> updatedDetectorMap = (HashMap<String, List>) (hit.getSourceAsMap().get("detector"));
        inputArr = updatedDetectorMap.get("inputs");

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        assertEquals(2, monitorIds.size());

        indexDoc(index, "1", randomDoc(2, 4, "Info"));
        indexDoc(index, "2", randomDoc(3, 4, "Info"));

        for (String monitorId : monitorIds) {
            Map<String, String> monitor = (Map<String, String>) (entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
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

        String findingDetectorId = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("index").toString();
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
                emptyList());
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
        Map<String, List> detectorMap = (HashMap<String, List>) (hit.getSourceAsMap().get("detector"));
        List inputArr = detectorMap.get("inputs");

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        // Test deleting the aggregation rule
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(avgRuleId)),
                emptyList());
        detector = randomDetectorWithInputs(List.of(newInput));
        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));

        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        Map<String, List> updatedDetectorMap = (HashMap<String, List>) (hit.getSourceAsMap().get("detector"));
        inputArr = updatedDetectorMap.get("inputs");

        assertEquals(1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        inputArr = updatedDetectorMap.get("inputs");

        assertEquals(1, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        // Verify monitors
        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        assertEquals(1, monitorIds.size());

        Map<String, String> monitor = (Map<String, String>) (entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorIds.get(0))))).get("monitor");

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

        String findingDetectorId = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);
    }

    /**
     * 1. Creates detector with 2 aggregation and prepackaged doc level rules
     * 2. Replaces one aggregation rule with a new one
     * 3. Verifies that number of rules is unchanged
     * 4. Verifies monitor types
     * 5. Verifies findings
     *
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
        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";

        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);
        Map<String, List> detectorMap = (HashMap<String, List>) (hit.getSourceAsMap().get("detector"));
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
        Map<String, List> updatedDetectorMap = (HashMap<String, List>) (hit.getSourceAsMap().get("detector"));
        inputArr = updatedDetectorMap.get("inputs");

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (updatedDetectorMap).get("monitor_id"));

        assertEquals(3, monitorIds.size());

        indexDoc(index, "1", randomDoc(2, 4, "Info"));
        indexDoc(index, "2", randomDoc(3, 4, "Info"));
        indexDoc(index, "3", randomDoc(3, 4, "Test"));
        Map<String, Integer> numberOfMonitorTypes = new HashMap<>();
        for (String monitorId : monitorIds) {
            Map<String, String> monitor = (Map<String, String>) (entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
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

        String findingDetectorId = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);

        List<String> docLevelFinding = new ArrayList<>();
        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");

        Set<String> docLevelRules = new HashSet<>(prepackagedDocRules);

        for (Map<String, Object> finding : findings) {
            List<Map<String, Object>> queries = (List<Map<String, Object>>) finding.get("queries");
            Set<String> findingRules = queries.stream().map(it -> it.get("id").toString()).collect(Collectors.toSet());
            // In this test case all doc level rules are matching the finding rule ids
            if (docLevelRules.containsAll(findingRules)) {
                docLevelFinding.addAll((List<String>) finding.get("related_doc_ids"));
            } else {
                String aggRuleId = findingRules.iterator().next();

                List<String> findingDocs = (List<String>) finding.get("related_doc_ids");
                Assert.assertEquals(2, findingDocs.size());
                assertTrue(Arrays.asList("1", "2").containsAll(findingDocs));
            }
        }
        // Verify doc level finding
        assertTrue(Arrays.asList("1", "2", "3").containsAll(docLevelFinding));
    }

    public void testMinAggregationRule_findingSuccess() throws IOException {
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

        List<String> aggRuleIds = new ArrayList<>();
        String testOpCode = "Test";
        aggRuleIds.add(createRule(randomAggregationRule("min", " > 3", testOpCode)));
        List<DetectorRule> detectorRules = aggRuleIds.stream().map(id -> new DetectorRule(id)).collect(Collectors.toList());
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
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
        Map<String, List> detectorMap = (HashMap<String, List>) (hit.getSourceAsMap().get("detector"));

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));

        indexDoc(index, "4", randomDoc(5, 3, testOpCode));
        indexDoc(index, "5", randomDoc(2, 3, testOpCode));
        indexDoc(index, "6", randomDoc(4, 3, testOpCode));
        indexDoc(index, "7", randomDoc(6, 2, testOpCode));
        indexDoc(index, "8", randomDoc(1, 1, testOpCode));

        Map<String, Integer> numberOfMonitorTypes = new HashMap<>();
        for (String monitorId : monitorIds) {
            Map<String, String> monitor = (Map<String, String>) (entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
            numberOfMonitorTypes.merge(monitor.get("monitor_type"), 1, Integer::sum);
            executeAlertingMonitor(monitorId, Collections.emptyMap());
        }

        // Verify findings
        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        assertNotNull(getFindingsBody);

        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");
        for (Map<String, Object> finding : findings) {
            List<String> findingDocs = (List<String>) finding.get("related_doc_ids");
            Assert.assertEquals(1, findingDocs.size());
            assertTrue(Arrays.asList("7").containsAll(findingDocs));
        }

        String findingDetectorId = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("index").toString();
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
        String maxRuleId = createRule(randomAggregationRule("max", " > 3", testOpCode));
        String minRuleId = createRule(randomAggregationRule("min", " > 3", testOpCode));
        String avgRuleId = createRule(randomAggregationRule("avg", " > 3", infoOpCode));
        String cntRuleId = createRule(randomAggregationRule("count", " > 3", "randomTestCode"));
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
        Map<String, List> updatedDetectorMap = (HashMap<String, List>) (hit.getSourceAsMap().get("detector"));
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

        for (String monitorId : monitorIds) {
            Map<String, String> monitor = (Map<String, String>) (entityAsMap(client().performRequest(new Request("GET", "/_plugins/_alerting/monitors/" + monitorId)))).get("monitor");
            numberOfMonitorTypes.merge(monitor.get("monitor_type"), 1, Integer::sum);
            Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());

            // Assert monitor executions
            Map<String, Object> executeResults = entityAsMap(executeResponse);
            if (MonitorType.DOC_LEVEL_MONITOR.getValue().equals(monitor.get("monitor_type")) && false == monitor.get("name").equals(detector.getName() + "_chained_findings")) {
                int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
                // 5 prepackaged and 1 custom doc level rule
                assertEquals(6, noOfSigmaRuleMatches);
            } else if (MonitorType.BUCKET_LEVEL_MONITOR.getValue().equals(monitor.get("monitor_type"))) {
                for (String ruleId : aggRuleIds) {
                    Object rule = (((Map<String, Object>) ((Map<String, Object>) ((List<Object>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0)).get("aggregations")).get(ruleId));
                    if (rule != null) {
                        if (ruleId == sumRuleId) {
                            assertRuleMonitorFinding(executeResults, ruleId, 3, List.of("4"));
                        } else if (ruleId == maxRuleId) {
                            assertRuleMonitorFinding(executeResults, ruleId, 5, List.of("2", "3"));
                        } else if (ruleId == minRuleId) {
                            assertRuleMonitorFinding(executeResults, ruleId, 1, List.of("2"));
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

        String findingDetectorId = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);

        List<String> docLevelFinding = new ArrayList<>();
        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");

        Set<String> docLevelRules = new HashSet<>(prepackagedRules);
        docLevelRules.add(randomDocRuleId);

        for (Map<String, Object> finding : findings) {
            List<Map<String, Object>> queries = (List<Map<String, Object>>) finding.get("queries");
            Set<String> findingRuleIds = queries.stream().map(it -> it.get("id").toString()).collect(Collectors.toSet());
            // Doc level finding matches all doc level rules (including the custom one) in this test case
            if (docLevelRules.containsAll(findingRuleIds)) {
                docLevelFinding.addAll((List<String>) finding.get("related_doc_ids"));
            } else {
                // In the case of bucket level monitors, queries will always contain one value
                String aggRuleId = findingRuleIds.iterator().next();
                List<String> findingDocs = (List<String>) finding.get("related_doc_ids");

                if (aggRuleId.equals(sumRuleId)) {
                    assertTrue(List.of("1", "2", "3").containsAll(findingDocs));
                } else if (aggRuleId.equals(maxRuleId)) {
                    assertTrue(List.of("4", "5", "6", "7").containsAll(findingDocs));
                } else if (aggRuleId.equals(minRuleId)) {
                    assertTrue(List.of("7").containsAll(findingDocs));
                }
            }
        }

        assertTrue(Arrays.asList("1", "2", "3", "4", "5", "6", "7", "8").containsAll(docLevelFinding));
    }

    public void testCreateDetector_verifyWorkflowCreation_success_WithoutGroupByRulesInTrigger() throws IOException {
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

        String maxRuleId = createRule(randomAggregationRule("max", " > 3", testOpCode));
        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId), new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
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

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(2, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 2);
    }

    public void testCreateDetector_verifyWorkflowCreation_success_WithGroupByRulesInTrigger() throws IOException {
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

        String maxRuleId = createRule(randomAggregationRule("max", " > 3", testOpCode));
        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId), new DetectorRule(randomDocRuleId));
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        DetectorTrigger t1 = new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(maxRuleId), List.of(), List.of(), List.of(), List.of());
        Detector detector = randomDetectorWithInputsAndTriggers(List.of(input), List.of(t1));

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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
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
        detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));

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

        String maxRuleId = createRule(randomAggregationRule("max", " > 3", testOpCode));
        String randomDocRuleId = createRule(randomRule());
        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId), new DetectorRule(randomDocRuleId));
        DetectorTrigger t1 = new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(randomDocRuleId, maxRuleId), List.of(), List.of(), List.of(), List.of());

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        Detector detector = randomDetectorWithInputsAndTriggers(List.of(input), List.of(t1));

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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
        List inputArr = (List) detectorMap.get("inputs");

        assertEquals(2, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(3, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 3);

        // Update detector - remove one agg rule; Verify workflow
        DetectorInput newInput = new DetectorInput("windows detector for security analytics", List.of("windows"), Arrays.asList(new DetectorRule(randomDocRuleId)), getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        detector = randomDetectorWithInputs(List.of(newInput));
        createResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(detector));

        assertEquals("Update detector failed", RestStatus.OK, restStatus(createResponse));
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);
        detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
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

        String findingDetectorId = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);

        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");

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

        String maxRuleId = createRule(randomAggregationRule("max", " > 3", testOpCode));
        String randomDocRuleId = createRule(randomRule());

        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId), new DetectorRule(randomDocRuleId));
        DetectorTrigger t1 = new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(randomDocRuleId, maxRuleId), List.of(), List.of(), List.of(), List.of());
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        Detector detector = randomDetectorWithInputsAndTriggers(List.of(input), List.of(t1));

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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
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

        String maxRuleId = createRule(randomAggregationRule("max", " > 3", testOpCode));
        String randomDocRuleId = createRule(randomRule());

        List<DetectorRule> detectorRules = List.of(new DetectorRule(maxRuleId), new DetectorRule(randomDocRuleId));
        DetectorTrigger t1, t2;
        t1 = new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(randomDocRuleId, maxRuleId), List.of(), List.of(), List.of(), List.of());
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                emptyList());
        Detector detector = randomDetectorWithInputsAndTriggers(List.of(input), List.of(t1));

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
        Map<String, Object> detectorMap = (HashMap<String, Object>) (hit.getSourceAsMap().get("detector"));
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
        assertEquals(6, getFindingsBody.get("total_findings"));

        String findingDetectorId = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("detectorId").toString();
        assertEquals(detectorId, findingDetectorId);

        String findingIndex = ((Map<String, Object>) ((List) getFindingsBody.get("findings")).get(0)).get("index").toString();
        assertEquals(index, findingIndex);

        List<String> docLevelFinding = new ArrayList<>();
        List<Map<String, Object>> findings = (List) getFindingsBody.get("findings");

        Set<String> docLevelRules = new HashSet<>(List.of(randomDocRuleId));
        for (Map<String, Object> finding : findings) {
            List<Map<String, Object>> queries = (List<Map<String, Object>>) finding.get("queries");
            Set<String> findingRules = queries.stream().map(it -> it.get("id").toString()).collect(Collectors.toSet());
            // In this test case all doc level rules are matching the finding rule ids
            if (docLevelRules.containsAll(findingRules)) {
                docLevelFinding.addAll((List<String>) finding.get("related_doc_ids"));
            } else {
                List<String> findingDocs = (List<String>) finding.get("related_doc_ids");
                Assert.assertEquals(4, findingDocs.size());
                assertTrue(Arrays.asList("1", "2", "3", "4").containsAll(findingDocs));
            }
        }
        // Verify doc level finding
        assertTrue(Arrays.asList("1", "2", "3", "4", "5").containsAll(docLevelFinding));
    }

    public void testCreateDetector_verifyWorkflowExecutionMultipleBucketLevelDocLevelMonitors_success_WithBucketLevelTriggersOnRuleIds() throws IOException {
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
        String maxRuleId = createRule(randomAggregationRule("max", " > 3", testOpCode));
        String minRuleId = createRule(randomAggregationRule("min", " > 3", testOpCode));
        String avgRuleId = createRule(randomAggregationRule("avg", " > 3", infoOpCode));
        String cntRuleId = createRule(randomAggregationRule("count", " > 3", "randomTestCode"));
        String randomDocRuleId = createRule(randomRule());
        List<String> prepackagedRules = getRandomPrePackagedRules();

        List<DetectorRule> detectorRules = List.of(new DetectorRule(sumRuleId), new DetectorRule(maxRuleId), new DetectorRule(minRuleId),
                new DetectorRule(avgRuleId), new DetectorRule(cntRuleId), new DetectorRule(randomDocRuleId));

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), detectorRules,
                prepackagedRules.stream().map(DetectorRule::new).collect(Collectors.toList()));
        DetectorTrigger t1, t2;
        t1 = new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(sumRuleId, maxRuleId), List.of(), List.of(), List.of(), List.of());
        t2 = new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(minRuleId, avgRuleId, cntRuleId), List.of(), List.of(), List.of(), List.of());
        Detector detector = randomDetectorWithInputsAndTriggers(List.of(input), List.of(t1, t2));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals(7, response.getHits().getTotalHits().value);

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

        assertEquals(6, ((Map<String, Map<String, List>>) inputArr.get(0)).get("detector_input").get("custom_rules").size());

        List<String> monitorIds = ((List<String>) (detectorMap).get("monitor_id"));
        assertEquals(7, monitorIds.size());

        assertNotNull("Workflow not created", detectorMap.get("workflow_ids"));
        assertEquals("Number of workflows not correct", 1, ((List<String>) detectorMap.get("workflow_ids")).size());

        indexDoc(index, "1", randomDoc(2, 4, infoOpCode));
        indexDoc(index, "2", randomDoc(3, 4, infoOpCode));
        indexDoc(index, "3", randomDoc(1, 4, infoOpCode));
        indexDoc(index, "4", randomDoc(5, 3, testOpCode));
        indexDoc(index, "5", randomDoc(2, 3, testOpCode));
        indexDoc(index, "6", randomDoc(4, 3, testOpCode));
        indexDoc(index, "7", randomDoc(6, 2, testOpCode));
        indexDoc(index, "8", randomDoc(1, 1, testOpCode));
        // Verify workflow
        verifyWorkflow(detectorMap, monitorIds, 7);

        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        HashMap<String, String> bucketMonitorsToRuleMap = (HashMap<String, String>) detectorMap.get("bucket_monitor_id_rule_id");
        String docMonitorId = bucketMonitorsToRuleMap.get("-1");
        String chainedFindingsMonitorId = bucketMonitorsToRuleMap.get("chained_findings_monitor");
        Map<String, String> monitorNameToIdMap = new HashMap<>();
        for (Map.Entry<String, String> entry : bucketMonitorsToRuleMap.entrySet()) {
            Response getMonitorRes = getAlertingMonitor(client(), entry.getValue());
            Map<String, Object> resMap = asMap(getMonitorRes);
            Map<String, Object> stringObjectMap = (Map<String, Object>) resMap.get("monitor");
            String name = stringObjectMap.get("name").toString();
            monitorNameToIdMap.put(name, entry.getValue());
        }


        Response executeResponse = executeAlertingWorkflow(workflowId, Collections.emptyMap());

        Map<String, Object> executeWorkflowResponseMap = entityAsMap(executeResponse);
        List<Map<String, Object>> monitorRunResults = (List<Map<String, Object>>) executeWorkflowResponseMap.get("monitor_run_results");

        for (Map<String, Object> runResult : monitorRunResults) {
            String monitorName = runResult.get("monitor_name").toString();
            String monitorId = monitorNameToIdMap.get(monitorName);
            if (monitorId.equals(docMonitorId)) {
                int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) runResult.get("input_results")).get("results")).get(0).size();
                // 5 prepackaged and 1 custom doc level rule
                assertEquals(6, noOfSigmaRuleMatches);
            } else if (monitorId.equals(chainedFindingsMonitorId)) {

            } else {
                Map<String, Object> trigger_results = (Map<String, Object>) runResult.get("trigger_results");
                if (trigger_results.containsKey(maxRuleId)) {
                    assertRuleMonitorFinding(runResult, maxRuleId, 5, List.of("2", "3"));
                } else if (trigger_results.containsKey(sumRuleId)) {
                    assertRuleMonitorFinding(runResult, sumRuleId, 3, List.of("4"));
                } else if (trigger_results.containsKey(minRuleId)) {
                    assertRuleMonitorFinding(runResult, minRuleId, 5, List.of("2"));
                }
            }
        }

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", detectorId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        // Assert findings
        assertNotNull(getFindingsBody);
        assertEquals(19, getFindingsBody.get("total_findings"));
    }

    public void testCreateDetectorWithKeywordsRule_verifyFindings_success() throws IOException {
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
        String randomDocRuleId = createRule(randomRuleWithKeywords());
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

        assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

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

    public void testCreateDetectorWithKeywordsRule_ensureNoFindingsWithoutTextMapping_success() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMappingOnlyNumericAndDate());

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
        String randomDocRuleId = createRule(randomRuleWithStringKeywords());
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(randomDocRuleId)),
                emptyList());
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

        assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

        // Verify rules created
        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals(1, response.getHits().getTotalHits().value);

        // Insert test document
        indexDoc(index, "1", randomDocOnlyNumericAndDate(2, 5, "Test"));
        indexDoc(index, "2", randomDocOnlyNumericAndDate(3, 5, "Test"));


        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        // Verify no rules match test document
        assertEquals(0, noOfSigmaRuleMatches);
    }

    public void testCreateDetectorWithKeywordsRule_ensureNoFindingsWithoutDateMapping_success() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMappingOnlyNumericAndText());

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
        String randomDocRuleId = createRule(randomRuleWithDateKeywords());
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(randomDocRuleId)),
                emptyList());
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

        assertEquals(MonitorType.DOC_LEVEL_MONITOR.getValue(), monitorType);

        // Verify rules created
        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        SearchResponse response = executeSearchAndGetResponse(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request, true);

        assertEquals(1, response.getHits().getTotalHits().value);

        // Insert test document
        indexDoc(index, "1", randomDocOnlyNumericAndText(2, 5, "Test"));
        indexDoc(index, "2", randomDocOnlyNumericAndText(3, 5, "Test"));


        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        // Verify no rules match test document
        assertEquals(0, noOfSigmaRuleMatches);
    }

    @SuppressWarnings("unchecked")
    public void testCreateDetectorWithCloudtrailAggrRule() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());
        indexDoc(index, "0", randomCloudtrailDoc("A12346", "CREATED"));

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

        String rule = randomCloudtrailAggrRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));
        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputsAndTriggers(List.of(input),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(createdId), List.of(), List.of(), List.of(), List.of())));

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

        String workflowId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("workflow_ids")).get(0);

        indexDoc(index, "1", randomCloudtrailDoc("A12345", "CREATED"));
        executeAlertingWorkflow(workflowId, Collections.emptyMap());
        indexDoc(index, "2", randomCloudtrailDoc("A12345", "DELETED"));
        executeAlertingWorkflow(workflowId, Collections.emptyMap());

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", createdId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        // Assert findings
        assertNotNull(getFindingsBody);
        assertEquals(1, getFindingsBody.get("total_findings"));
    }

    @SuppressWarnings("unchecked")
    public void testCreateDetectorWithCloudtrailAggrRuleWithDotFields() throws IOException {
        String index = createTestIndex("cloudtrail", cloudtrailOcsfMappings());
        indexDoc(index, "0", randomCloudtrailOcsfDoc());

        String rule = randomCloudtrailAggrRuleWithDotFields();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "cloudtrail"),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));
        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("cloudtrail detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputsAndTriggers(List.of(input),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(createdId), List.of(), List.of(), List.of(), List.of())));

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

        String workflowId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("workflow_ids")).get(0);

        indexDoc(index, "1", randomCloudtrailOcsfDoc());
        indexDoc(index, "2", randomCloudtrailOcsfDoc());
        executeAlertingWorkflow(workflowId, Collections.emptyMap());

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", createdId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        // Assert findings
        assertNotNull(getFindingsBody);
        assertEquals(1, getFindingsBody.get("total_findings"));
    }

    @SuppressWarnings("unchecked")
    public void testCreateDetectorWithCloudtrailAggrRuleWithEcsFields() throws IOException {
        String index = createTestIndex("cloudtrail", cloudtrailOcsfMappings());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{\n" +
                        "  \"index_name\": \"cloudtrail\",\n" +
                        "  \"rule_topic\": \"cloudtrail\",\n" +
                        "  \"partial\": true,\n" +
                        "  \"alias_mappings\": {\n" +
                        "    \"properties\": {\n" +
                        "      \"aws.cloudtrail.event_name\": {\n" +
                        "        \"path\": \"api.operation\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      },\n" +
                        "      \"aws.cloudtrail.event_source\": {\n" +
                        "        \"path\": \"api.service.name\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      },\n" +
                        "      \"aws.cloudtrail.aws_region\": {\n" +
                        "        \"path\": \"cloud.region\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      }\n" +
                        "    }\n" +
                        "  }\n" +
                        "}"
        );

        Response createMappingResponse = client().performRequest(createMappingRequest);

        assertEquals(HttpStatus.SC_OK, createMappingResponse.getStatusLine().getStatusCode());
        indexDoc(index, "0", randomCloudtrailOcsfDoc());

        String rule = randomCloudtrailAggrRuleWithEcsFields();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "cloudtrail"),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));
        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("cloudtrail detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputsAndTriggers(List.of(input),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(createdId), List.of(), List.of(), List.of(), List.of())));

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

        String workflowId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("workflow_ids")).get(0);

        indexDoc(index, "1", randomCloudtrailOcsfDoc());
        indexDoc(index, "2", randomCloudtrailOcsfDoc());
        executeAlertingWorkflow(workflowId, Collections.emptyMap());

        Map<String, String> params = new HashMap<>();
        params.put("detector_id", createdId);
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        // Assert findings
        assertNotNull(getFindingsBody);
        assertEquals(1, getFindingsBody.get("total_findings"));
    }

    private static void assertRuleMonitorFinding(Map<String, Object> executeResults, String ruleId, int expectedDocCount, List<String> expectedTriggerResult) {
        List<Map<String, Object>> buckets = ((List<Map<String, Object>>) (((Map<String, Object>) ((Map<String, Object>) ((Map<String, Object>) ((List<Object>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0)).get("aggregations")).get("result_agg")).get("buckets")));
        Integer docCount = buckets.stream().mapToInt(it -> (Integer) it.get("doc_count")).sum();
        assertEquals(expectedDocCount, docCount.intValue());

        List<String> triggerResultBucketKeys = ((Map<String, Object>) ((Map<String, Object>) ((Map<String, Object>) executeResults.get("trigger_results")).get(ruleId)).get("agg_result_buckets")).keySet().stream().collect(Collectors.toList());
        Assert.assertEquals(expectedTriggerResult, triggerResultBucketKeys);
    }
}