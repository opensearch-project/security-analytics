/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.alerts;

import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.junit.Assert;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.commons.alerting.model.CorrelationAlert;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import static org.opensearch.securityanalytics.TestHelpers.cloudtrailMappings;
import static org.opensearch.securityanalytics.TestHelpers.randomCloudtrailDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomCloudtrailRuleForCorrelations;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputsAndTriggersAndType;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomVpcFlowDoc;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;


public class CorrelationAlertsRestApiIT  extends SecurityAnalyticsRestTestCase {

    public void testGetCorrelationAlertsAPI() throws IOException, InterruptedException {
        LogIndices indices = createIndices();

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String testWindowsMonitorId = createTestWindowsDetector(indices.windowsIndex);

        createNetworkToAdLdapToWindowsRuleWithTrigger(indices);
        Thread.sleep(5000);

        indexDoc(indices.windowsIndex, "2", randomDoc());
        Response executeResponse = executeAlertingMonitor(testWindowsMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);

        Thread.sleep(5000);
        indexDoc(indices.vpcFlowsIndex, "1", randomVpcFlowDoc());
        executeResponse = executeAlertingMonitor(vpcFlowMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        Thread.sleep(5000);

        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        Long endTime = System.currentTimeMillis();
                        Request request = new Request("GET", "/_plugins/_security_analytics/correlationAlerts");
                        Response response = client().performRequest(request);

                        Map<String, Object> responseMap = entityAsMap(response);
                        List<CorrelationAlert> correlationAlerts = (List<CorrelationAlert>) responseMap.get("correlationAlerts");
                        if (correlationAlerts.size() == 1) {
                            Assert.assertEquals(correlationAlerts.get(0).getTriggerName(), "Trigger 1");
                            Assert.assertTrue(true);
                            return true;
                        }
                        return false;
                    } catch (Exception ex) {
                        return false;
                    }
                },
                2, TimeUnit.MINUTES
        );
    }

    public void testGetCorrelationAlertsByRuleIdAPI() throws IOException, InterruptedException {
        String index = createTestIndex("cloudtrail", cloudtrailMappings());
        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{\n" +
                        "  \"index_name\": \"" + index + "\",\n" +
                        "  \"rule_topic\": \"cloudtrail\",\n" +
                        "  \"partial\": true,\n" +
                        "  \"alias_mappings\": {\n" +
                        "    \"properties\": {\n" +
                        "      \"aws.cloudtrail.event_name\": {\n" +
                        "        \"path\": \"Records.eventName\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      }\n" +
                        "    }\n" +
                        "  }\n" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusLine().getStatusCode());

        String rule1 = randomCloudtrailRuleForCorrelations("CreateUser");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "cloudtrail"),
                new StringEntity(rule1), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));
        Map<String, Object> responseBody = asMap(createResponse);
        String createdId1 = responseBody.get("_id").toString();

        String rule2 = randomCloudtrailRuleForCorrelations("DeleteUser");
        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "cloudtrail"),
                new StringEntity(rule2), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));
        responseBody = asMap(createResponse);
        String createdId2 = responseBody.get("_id").toString();

        createCloudtrailFieldBasedRuleWithTrigger(index, "requestParameters.userName", null);

        Detector cloudtrailDetector = randomDetectorWithInputsAndTriggersAndType(List.of(new DetectorInput("cloudtrail detector for security analytics", List.of(index),
                        List.of(new DetectorRule(createdId1), new DetectorRule(createdId2)),
                        List.of())),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("cloudtrail"), List.of(), List.of(), List.of(), List.of(), List.of())), "cloudtrail");

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(cloudtrailDetector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

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

        indexDoc(index, "1", randomCloudtrailDoc("Richard", "CreateUser"));
        executeAlertingMonitor(monitorId, Collections.emptyMap());
        Thread.sleep(1000);
        indexDoc(index, "4", randomCloudtrailDoc("deysubho", "CreateUser"));
        executeAlertingMonitor(monitorId, Collections.emptyMap());
        Thread.sleep(1000);

        indexDoc(index, "2", randomCloudtrailDoc("Richard", "DeleteUser"));
        executeAlertingMonitor(monitorId, Collections.emptyMap());

        Thread.sleep(5000);

        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        Request restRequest = new Request("GET", "/_plugins/_security_analytics/correlationAlerts?correlation_rule_id=correlation-rule-1");
                        Response restResponse = client().performRequest(restRequest);

                        Map<String, Object> responseMap = entityAsMap(restResponse);
                        int totalAlerts = (int) responseMap.get("total_alerts");
                        if (totalAlerts == 1) {
                            Assert.assertTrue(true);
                            return true;
                        }
                        return false;
                    } catch (Exception ex) {
                        return false;
                    }
                },
                2, TimeUnit.MINUTES
        );
    }

    public void testGetCorrelationAlertsAcknowledgeAPI() throws IOException, InterruptedException {
        String index = createTestIndex("cloudtrail", cloudtrailMappings());
        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{\n" +
                        "  \"index_name\": \"" + index + "\",\n" +
                        "  \"rule_topic\": \"cloudtrail\",\n" +
                        "  \"partial\": true,\n" +
                        "  \"alias_mappings\": {\n" +
                        "    \"properties\": {\n" +
                        "      \"aws.cloudtrail.event_name\": {\n" +
                        "        \"path\": \"Records.eventName\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      }\n" +
                        "    }\n" +
                        "  }\n" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusLine().getStatusCode());

        String rule1 = randomCloudtrailRuleForCorrelations("CreateUser");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "cloudtrail"),
                new StringEntity(rule1), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));
        Map<String, Object> responseBody = asMap(createResponse);
        String createdId1 = responseBody.get("_id").toString();

        String rule2 = randomCloudtrailRuleForCorrelations("DeleteUser");
        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "cloudtrail"),
                new StringEntity(rule2), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));
        responseBody = asMap(createResponse);
        String createdId2 = responseBody.get("_id").toString();

        createCloudtrailFieldBasedRuleWithTrigger(index, "requestParameters.userName", null);

        Detector cloudtrailDetector = randomDetectorWithInputsAndTriggersAndType(List.of(new DetectorInput("cloudtrail detector for security analytics", List.of(index),
                        List.of(new DetectorRule(createdId1), new DetectorRule(createdId2)),
                        List.of())),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("cloudtrail"), List.of(), List.of(), List.of(), List.of(), List.of())), "cloudtrail");

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(cloudtrailDetector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

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

        indexDoc(index, "1", randomCloudtrailDoc("Richard", "CreateUser"));
        executeAlertingMonitor(monitorId, Collections.emptyMap());
        Thread.sleep(1000);
        indexDoc(index, "4", randomCloudtrailDoc("John", "CreateUser"));
        executeAlertingMonitor(monitorId, Collections.emptyMap());
        Thread.sleep(1000);

        indexDoc(index, "2", randomCloudtrailDoc("Richard", "DeleteUser"));
        executeAlertingMonitor(monitorId, Collections.emptyMap());

        Thread.sleep(5000);
        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        Request request1 = new Request("GET", "/_plugins/_security_analytics/correlationAlerts");
                        Response getCorrelationAlertResp = client().performRequest(request1);
                        Map<String, Object> responseGetCorrelationAlertMap = entityAsMap(getCorrelationAlertResp);
                        List<CorrelationAlert> correlationAlerts = (List<CorrelationAlert>) responseGetCorrelationAlertMap.get("correlationAlerts");
                        // Execute CreateMappingsAction to add alias mapping for index
                        Thread.sleep(2000);
                        Request restRequest = new Request("POST", "/_plugins/_security_analytics/_acknowledge/correlationAlerts");
                        restRequest.setJsonEntity(
                                "{\"alertIds\": [\"" + correlationAlerts.get(0).getId() + "\"]}"
                        );
                        Response restResponse = client().performRequest(restRequest);
                        Map<String, Object> responseMap = entityAsMap(restResponse);
                        List<Object> results = (List<Object>) responseMap.get("acknowledged");
                        if (results.size() == 1) {
                            Assert.assertTrue(true);
                            return true;
                        }
                        return false;
                    } catch (Exception ex) {
                        return false;
                    }
                },
                2, TimeUnit.MINUTES
        );
    }
}
