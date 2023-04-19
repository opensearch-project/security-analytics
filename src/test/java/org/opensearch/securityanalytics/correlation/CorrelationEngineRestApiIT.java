/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation;

import org.junit.Assert;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.model.CorrelationQuery;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.TestHelpers.*;

public class CorrelationEngineRestApiIT extends SecurityAnalyticsRestTestCase {

    @SuppressWarnings("unchecked")
    public void testBasicCorrelationEngineWorkflow() throws IOException, InterruptedException {
        LogIndices indices = createIndices();

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String adLdapMonitorId = createAdLdapDetector(indices.adLdapLogsIndex);
        String testWindowsMonitorId = createTestWindowsDetector(indices.windowsIndex);
        String appLogsMonitorId = createAppLogsDetector(indices.appLogsIndex);
        String s3MonitorId = createS3Detector(indices.s3AccessLogsIndex);

        createNetworkToAdLdapToWindowsRule(indices);
        createWindowsToAppLogsToS3LogsRule(indices);

        indexDoc(indices.vpcFlowsIndex, "1", randomVpcFlowDoc());
        Response executeResponse = executeAlertingMonitor(vpcFlowMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        Thread.sleep(2000);

        indexDoc(indices.adLdapLogsIndex, "22", randomAdLdapDoc());
        executeResponse = executeAlertingMonitor(adLdapMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(0, noOfSigmaRuleMatches);

        indexDoc(indices.windowsIndex, "2", randomDoc());
        executeResponse = executeAlertingMonitor(testWindowsMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);

        indexDoc(indices.appLogsIndex, "4", randomAppLogDoc());
        executeResponse = executeAlertingMonitor(appLogsMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(0, noOfSigmaRuleMatches);

        indexDoc(indices.s3AccessLogsIndex, "5", randomS3AccessLogDoc());
        executeResponse = executeAlertingMonitor(s3MonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(0, noOfSigmaRuleMatches);

        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", "test_windows");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        String finding = ((List<Map<String, Object>>) getFindingsBody.get("findings")).get(0).get("id").toString();

        List<Map<String, Object>> correlatedFindings = searchCorrelatedFindings(finding, "test_windows", 300000L, 10);
        Assert.assertEquals(1, correlatedFindings.size());
    }

    @SuppressWarnings("unchecked")
    public void testListCorrelationsWorkflow() throws IOException, InterruptedException {
        Long startTime = System.currentTimeMillis();
        LogIndices indices = createIndices();

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String testWindowsMonitorId = createTestWindowsDetector(indices.windowsIndex);

        createNetworkToAdLdapToWindowsRule(indices);
        Thread.sleep(30000);

        indexDoc(indices.vpcFlowsIndex, "1", randomVpcFlowDoc());
        Response executeResponse = executeAlertingMonitor(vpcFlowMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        Thread.sleep(30000);

        indexDoc(indices.windowsIndex, "2", randomDoc());
        executeResponse = executeAlertingMonitor(testWindowsMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);

        Thread.sleep(30000);
        Long endTime = System.currentTimeMillis();

        Request request = new Request("GET", "/_plugins/_security_analytics/correlations?start_timestamp=" + startTime + "&end_timestamp=" + endTime);
        Response response = client().performRequest(request);

        Assert.assertEquals(200, response.getStatusLine().getStatusCode());
        Map<String, Object> responseMap = entityAsMap(response);
        List<Object> results = (List<Object>) responseMap.get("findings");
        Assert.assertEquals(1, results.size());
    }

    private LogIndices createIndices() throws IOException {
        LogIndices indices = new LogIndices();
        indices.adLdapLogsIndex = createTestIndex("ad_logs", adLdapLogMappings());
        indices.s3AccessLogsIndex = createTestIndex("s3_access_logs", s3AccessLogMappings());
        indices.appLogsIndex = createTestIndex("app_logs", appLogMappings());
        indices.windowsIndex = createTestIndex(randomIndex(), windowsIndexMapping());
        indices.vpcFlowsIndex = createTestIndex("vpc_flow", vpcFlowMappings());
        return indices;
    }

    private void createNetworkToAdLdapToWindowsRule(LogIndices indices) throws IOException {
        CorrelationQuery query1 = new CorrelationQuery(indices.vpcFlowsIndex, "dstaddr:4.5.6.7", "network");
        CorrelationQuery query2 = new CorrelationQuery(indices.adLdapLogsIndex, "ResultType:50126", "ad_ldap");
        CorrelationQuery query4 = new CorrelationQuery(indices.windowsIndex, "Domain:NTAUTHORI*", "test_windows");

        CorrelationRule rule = new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, "network to ad_ldap to windows", List.of(query1, query2, query4));
        Request request = new Request("POST", "/_plugins/_security_analytics/correlation/rules");
        request.setJsonEntity(toJsonString(rule));
        Response response = client().performRequest(request);

        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
    }

    private void createWindowsToAppLogsToS3LogsRule(LogIndices indices) throws IOException {
        CorrelationQuery query1 = new CorrelationQuery(indices.windowsIndex, "HostName:EC2AMAZ-EPO7HKA", "test_windows");
        CorrelationQuery query2 = new CorrelationQuery(indices.appLogsIndex, "endpoint:\\/customer_records.txt", "ad_ldap");
        CorrelationQuery query4 = new CorrelationQuery(indices.s3AccessLogsIndex, "aws.cloudtrail.eventName:ReplicateObject", "s3");

        CorrelationRule rule = new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, "windows to app_logs to s3 logs", List.of(query1, query2, query4));
        Request request = new Request("POST", "/_plugins/_security_analytics/correlation/rules");
        request.setJsonEntity(toJsonString(rule));
        Response response = client().performRequest(request);

        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
    }

    @SuppressWarnings("unchecked")
    private String createVpcFlowDetector(String indexName) throws IOException {
        Detector vpcFlowDetector = randomDetectorWithInputsAndTriggersAndType(List.of(new DetectorInput("vpc flow detector for security analytics", List.of(indexName), List.of(),
                        getPrePackagedRules("network").stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("network"), List.of(), List.of(), List.of(), List.of())), Detector.DetectorType.NETWORK);

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(vpcFlowDetector));
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

        return  ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
    }

    @SuppressWarnings("unchecked")
    private String createAdLdapDetector(String indexName) throws IOException {
        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{\n" +
                        "  \"index_name\": \"" + indexName + "\",\n" +
                        "  \"rule_topic\": \"ad_ldap\",\n" +
                        "  \"partial\": true,\n" +
                        "  \"alias_mappings\": {\n" +
                        "    \"properties\": {\n" +
                        "      \"azure-signinlogs-properties-user_id\": {\n" +
                        "        \"path\": \"azure.signinlogs.props.user_id\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      },\n" +
                        "      \"azure-platformlogs-result_type\": {\n" +
                        "        \"path\": \"azure.platformlogs.result_type\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      },\n" +
                        "      \"azure-signinlogs-result_description\": {\n" +
                        "        \"path\": \"azure.signinlogs.result_description\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      },\n" +
                        "      \"timestamp\": {\n" +
                        "        \"path\": \"creationTime\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      }\n" +
                        "    }\n" +
                        "  }\n" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusLine().getStatusCode());

        Detector adLdapDetector = randomDetectorWithInputsAndTriggersAndType(List.of(new DetectorInput("ad_ldap logs detector for security analytics", List.of(indexName), List.of(),
                        getPrePackagedRules("ad_ldap").stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("ad_ldap"), List.of(), List.of(), List.of(), List.of())), Detector.DetectorType.AD_LDAP);

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(adLdapDetector));
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

        return  ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
    }

    @SuppressWarnings("unchecked")
    private String createTestWindowsDetector(String indexName) throws IOException {
        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + indexName + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusLine().getStatusCode());

        Detector windowsDetector = randomDetectorWithInputsAndTriggers(List.of(new DetectorInput("windows detector for security analytics", List.of(indexName), List.of(),
                        getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(windowsDetector));
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

        return ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
    }

    @SuppressWarnings("unchecked")
    private String createAppLogsDetector(String indexName) throws IOException {
        Detector appLogsDetector = randomDetectorWithInputsAndTriggersAndType(List.of(new DetectorInput("app logs detector for security analytics", List.of(indexName), List.of(),
                        getPrePackagedRules("others_application").stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("others_application"), List.of(), List.of(), List.of(), List.of())), Detector.DetectorType.OTHERS_APPLICATION);

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(appLogsDetector));
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

        return ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
    }

    @SuppressWarnings("unchecked")
    private String createS3Detector(String indexName) throws IOException {
        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{\n" +
                        "  \"index_name\": \"s3_access_logs\",\n" +
                        "  \"rule_topic\": \"s3\",\n" +
                        "  \"partial\": true,\n" +
                        "  \"alias_mappings\": {\n" +
                        "    \"properties\": {\n" +
                        "      \"aws-cloudtrail-event_source\": {\n" +
                        "        \"type\": \"alias\",\n" +
                        "        \"path\": \"aws.cloudtrail.event_source\"\n" +
                        "      },\n" +
                        "      \"aws.cloudtrail.event_name\": {\n" +
                        "        \"type\": \"alias\",\n" +
                        "        \"path\": \"aws.cloudtrail.event_name\"\n" +
                        "      }\n" +
                        "    }\n" +
                        "  }\n" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusLine().getStatusCode());

        Detector s3AccessLogsDetector = randomDetectorWithInputsAndTriggersAndType(List.of(new DetectorInput("s3 access logs detector for security analytics", List.of(indexName), List.of(),
                        getPrePackagedRules("s3").stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("s3"), List.of(), List.of(), List.of(), List.of())), Detector.DetectorType.S3);

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(s3AccessLogsDetector));
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

        return ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
    }

    static class LogIndices {
        String vpcFlowsIndex;
        String adLdapLogsIndex;
        String windowsIndex;
        String appLogsIndex;
        String s3AccessLogsIndex;
    }
}