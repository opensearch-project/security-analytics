/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation;

import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.Assert;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.opensearch.securityanalytics.TestHelpers.*;

public class CorrelationEngineRestApiIT extends SecurityAnalyticsRestTestCase {

    @SuppressWarnings("unchecked")
    public void testBasicCorrelationEngineWorkflow() throws IOException, InterruptedException {
        updateClusterSetting(SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS.getKey(), "true");

        LogIndices indices = createIndices();

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String adLdapMonitorId = createAdLdapDetector(indices.adLdapLogsIndex);
        String testWindowsMonitorId = createTestWindowsDetector(indices.windowsIndex);
        String appLogsMonitorId = createAppLogsDetector(indices.appLogsIndex);
        String s3MonitorId = createS3Detector(indices.s3AccessLogsIndex);

        String ruleId = createNetworkToAdLdapToWindowsRule(indices);
        createWindowsToAppLogsToS3LogsRule(indices);

        indexDoc(indices.adLdapLogsIndex, "22", randomAdLdapDoc());
        Response executeResponse = executeAlertingMonitor(adLdapMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

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

        indexDoc(indices.vpcFlowsIndex, "1", randomVpcFlowDoc());
        executeResponse = executeAlertingMonitor(vpcFlowMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
        Thread.sleep(5000);

        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", "test_windows");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        String finding = ((List<Map<String, Object>>) getFindingsBody.get("findings")).get(0).get("id").toString();

        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        List<Map<String, Object>> correlatedFindings = searchCorrelatedFindings(finding, "test_windows", 300000L, 10);
                        if (correlatedFindings.size() == 2) {
                            Assert.assertTrue(true);

                            Assert.assertTrue(correlatedFindings.get(0).get("rules") instanceof List);

                            for (var correlatedFinding: correlatedFindings) {
                                if (correlatedFinding.get("detector_type").equals("network")) {
                                    Assert.assertEquals(1, ((List<String>) correlatedFinding.get("rules")).size());
                                    Assert.assertTrue(((List<String>) correlatedFinding.get("rules")).contains(ruleId));
                                }
                            }
                            return true;
                        }
                        return false;
                    } catch (Exception ex) {
                        return true;
                    }
                },
                2, TimeUnit.MINUTES
        );
    }

    @SuppressWarnings("unchecked")
    public void testListCorrelationsWorkflow() throws IOException, InterruptedException {
        Long startTime = System.currentTimeMillis();
        LogIndices indices = createIndices();

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String testWindowsMonitorId = createTestWindowsDetector(indices.windowsIndex);

        createNetworkToAdLdapToWindowsRule(indices);
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
                        Request request = new Request("GET", "/_plugins/_security_analytics/correlations?start_timestamp=" + startTime + "&end_timestamp=" + endTime);
                        Response response = client().performRequest(request);

                        Map<String, Object> responseMap = entityAsMap(response);
                        List<Object> results = (List<Object>) responseMap.get("findings");
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

    @SuppressWarnings("unchecked")
    public void testBasicCorrelationEngineWorkflowWithoutRules() throws IOException, InterruptedException {
        updateClusterSetting(SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS.getKey(), "true");
        LogIndices indices = createIndices();

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String adLdapMonitorId = createAdLdapDetector(indices.adLdapLogsIndex);
        String testWindowsMonitorId = createTestWindowsDetector(indices.windowsIndex);
        String appLogsMonitorId = createAppLogsDetector(indices.appLogsIndex);
        String s3MonitorId = createS3Detector(indices.s3AccessLogsIndex);

        indexDoc(indices.adLdapLogsIndex, "22", randomAdLdapDoc());
        Response executeResponse = executeAlertingMonitor(adLdapMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

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

        indexDoc(indices.vpcFlowsIndex, "1", randomVpcFlowDoc());
        executeResponse = executeAlertingMonitor(vpcFlowMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", "test_windows");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        String finding = ((List<Map<String, Object>>) getFindingsBody.get("findings")).get(0).get("id").toString();

        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        List<Map<String, Object>> correlatedFindings = searchCorrelatedFindings(finding, "test_windows", 300000L, 10);
                        if (correlatedFindings.size() == 2) {
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

    @SuppressWarnings("unchecked")
    public void testBasicCorrelationEngineWorkflowWithRolloverByMaxAge() throws IOException, InterruptedException {
        updateClusterSetting(SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS.getKey(), "true");
        updateClusterSetting(SecurityAnalyticsSettings.CORRELATION_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(SecurityAnalyticsSettings.CORRELATION_HISTORY_INDEX_MAX_AGE.getKey(), "1s");

        LogIndices indices = createIndices();

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String adLdapMonitorId = createAdLdapDetector(indices.adLdapLogsIndex);
        String testWindowsMonitorId = createTestWindowsDetector(indices.windowsIndex);
        String appLogsMonitorId = createAppLogsDetector(indices.appLogsIndex);
        String s3MonitorId = createS3Detector(indices.s3AccessLogsIndex);

        String ruleId = createNetworkToAdLdapToWindowsRule(indices);
        createWindowsToAppLogsToS3LogsRule(indices);

        indexDoc(indices.adLdapLogsIndex, "22", randomAdLdapDoc());
        Response executeResponse = executeAlertingMonitor(adLdapMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.windowsIndex, "2", randomDoc());
        executeResponse = executeAlertingMonitor(testWindowsMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.appLogsIndex, "4", randomAppLogDoc());
        executeResponse = executeAlertingMonitor(appLogsMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(0, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.s3AccessLogsIndex, "5", randomS3AccessLogDoc());
        executeResponse = executeAlertingMonitor(s3MonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(0, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.vpcFlowsIndex, "1", randomVpcFlowDoc());
        executeResponse = executeAlertingMonitor(vpcFlowMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", "test_windows");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        String finding = ((List<Map<String, Object>>) getFindingsBody.get("findings")).get(0).get("id").toString();
        Thread.sleep(1000L);

        OpenSearchRestTestCase.waitUntil(
                new BooleanSupplier() {
                    @Override
                    public boolean getAsBoolean() {
                        try {
                            List<Map<String, Object>> correlatedFindings = searchCorrelatedFindings(finding, "test_windows", 300000L, 10);
                            if (correlatedFindings.size() == 2) {
                                Assert.assertTrue(true);

                                Assert.assertTrue(correlatedFindings.get(0).get("rules") instanceof List);

                                for (var correlatedFinding: correlatedFindings) {
                                    if (correlatedFinding.get("detector_type").equals("network")) {
                                        Assert.assertEquals(1, ((List<String>) correlatedFinding.get("rules")).size());
                                        Assert.assertTrue(((List<String>) correlatedFinding.get("rules")).contains(ruleId));
                                    }
                                }

                                List<String> correlationIndices = getCorrelationHistoryIndices();
                                while (correlationIndices.size() < 2) {
                                    correlationIndices = getCorrelationHistoryIndices();
                                    Thread.sleep(1000);
                                }
                                Assert.assertTrue("Did not find more then 2 correlation indices", correlationIndices.size() >= 2);
                                return true;
                            }
                            return false;
                        } catch (Exception ex) {
                            return false;
                        }
                    }
                },
                2, TimeUnit.MINUTES
        );
    }

    public void testBasicCorrelationEngineWorkflowWithRolloverByMaxDoc() throws IOException, InterruptedException {
        updateClusterSetting(SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS.getKey(), "true");
        updateClusterSetting(SecurityAnalyticsSettings.CORRELATION_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(SecurityAnalyticsSettings.CORRELATION_HISTORY_MAX_DOCS.getKey(), "1");

        LogIndices indices = createIndices();

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String adLdapMonitorId = createAdLdapDetector(indices.adLdapLogsIndex);
        String testWindowsMonitorId = createTestWindowsDetector(indices.windowsIndex);
        String appLogsMonitorId = createAppLogsDetector(indices.appLogsIndex);
        String s3MonitorId = createS3Detector(indices.s3AccessLogsIndex);

        String ruleId = createNetworkToAdLdapToWindowsRule(indices);
        createWindowsToAppLogsToS3LogsRule(indices);

        indexDoc(indices.adLdapLogsIndex, "22", randomAdLdapDoc());
        Response executeResponse = executeAlertingMonitor(adLdapMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.windowsIndex, "2", randomDoc());
        executeResponse = executeAlertingMonitor(testWindowsMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.appLogsIndex, "4", randomAppLogDoc());
        executeResponse = executeAlertingMonitor(appLogsMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(0, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.s3AccessLogsIndex, "5", randomS3AccessLogDoc());
        executeResponse = executeAlertingMonitor(s3MonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(0, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.vpcFlowsIndex, "1", randomVpcFlowDoc());
        executeResponse = executeAlertingMonitor(vpcFlowMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", "test_windows");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        String finding = ((List<Map<String, Object>>) getFindingsBody.get("findings")).get(0).get("id").toString();
        Thread.sleep(1000L);

        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        List<Map<String, Object>> correlatedFindings = searchCorrelatedFindings(finding, "test_windows", 300000L, 10);
                        if (correlatedFindings.size() == 2) {
                            Assert.assertTrue(true);

                            Assert.assertTrue(correlatedFindings.get(0).get("rules") instanceof List);

                            for (var correlatedFinding: correlatedFindings) {
                                if (correlatedFinding.get("detector_type").equals("network")) {
                                    Assert.assertEquals(1, ((List<String>) correlatedFinding.get("rules")).size());
                                    Assert.assertTrue(((List<String>) correlatedFinding.get("rules")).contains(ruleId));
                                }
                            }

                            List<String> correlationIndices = getCorrelationHistoryIndices();
                            while (correlationIndices.size() < 2) {
                                correlationIndices = getCorrelationHistoryIndices();
                                Thread.sleep(1000);
                            }
                            Assert.assertTrue("Did not find more then 2 correlation indices", correlationIndices.size() >= 2);
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

    public void testBasicCorrelationEngineWorkflowWithRolloverByMaxDocAndShortRetention() throws IOException, InterruptedException {
        updateClusterSetting(SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS.getKey(), "true");
        updateClusterSetting(SecurityAnalyticsSettings.CORRELATION_HISTORY_ROLLOVER_PERIOD.getKey(), "1s");
        updateClusterSetting(SecurityAnalyticsSettings.CORRELATION_HISTORY_MAX_DOCS.getKey(), "1");

        LogIndices indices = createIndices();

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String adLdapMonitorId = createAdLdapDetector(indices.adLdapLogsIndex);
        String testWindowsMonitorId = createTestWindowsDetector(indices.windowsIndex);
        String appLogsMonitorId = createAppLogsDetector(indices.appLogsIndex);
        String s3MonitorId = createS3Detector(indices.s3AccessLogsIndex);

        String ruleId = createNetworkToAdLdapToWindowsRule(indices);
        createWindowsToAppLogsToS3LogsRule(indices);

        indexDoc(indices.adLdapLogsIndex, "22", randomAdLdapDoc());
        Response executeResponse = executeAlertingMonitor(adLdapMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.windowsIndex, "2", randomDoc());
        executeResponse = executeAlertingMonitor(testWindowsMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.appLogsIndex, "4", randomAppLogDoc());
        executeResponse = executeAlertingMonitor(appLogsMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(0, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.s3AccessLogsIndex, "5", randomS3AccessLogDoc());
        executeResponse = executeAlertingMonitor(s3MonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(0, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        indexDoc(indices.vpcFlowsIndex, "1", randomVpcFlowDoc());
        executeResponse = executeAlertingMonitor(vpcFlowMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
        Thread.sleep(1000L);

        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", "test_windows");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        String finding = ((List<Map<String, Object>>) getFindingsBody.get("findings")).get(0).get("id").toString();
        Thread.sleep(1000L);

        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        List<Map<String, Object>> correlatedFindings = searchCorrelatedFindings(finding, "test_windows", 300000L, 10);
                        if (correlatedFindings.size() == 2) {
                            Assert.assertTrue(true);

                            Assert.assertTrue(correlatedFindings.get(0).get("rules") instanceof List);

                            for (var correlatedFinding: correlatedFindings) {
                                if (correlatedFinding.get("detector_type").equals("network")) {
                                    Assert.assertEquals(1, ((List<String>) correlatedFinding.get("rules")).size());
                                    Assert.assertTrue(((List<String>) correlatedFinding.get("rules")).contains(ruleId));
                                }
                            }

                            List<String> correlationIndices = getCorrelationHistoryIndices();
                            while (correlationIndices.size() < 2) {
                                correlationIndices = getCorrelationHistoryIndices();
                                Thread.sleep(1000);
                            }
                            Assert.assertTrue("Did not find more then 2 correlation indices", correlationIndices.size() >= 2);

                            updateClusterSetting(SecurityAnalyticsSettings.CORRELATION_HISTORY_RETENTION_PERIOD.getKey(), "1s");
                            updateClusterSetting(SecurityAnalyticsSettings.CORRELATION_HISTORY_MAX_DOCS.getKey(), "1000");

                            while (correlationIndices.size() != 1) {
                                correlationIndices = getCorrelationHistoryIndices();
                                Thread.sleep(1000);
                            }
                            Assert.assertTrue("Found more than 1 correlation indices", correlationIndices.size() == 1);
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

    public void testBasicCorrelationEngineWorkflowWithFieldBasedRules() throws IOException, InterruptedException {
        Long startTime = System.currentTimeMillis();
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

        createCloudtrailFieldBasedRule(index, "requestParameters.userName", null);

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

        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", "cloudtrail");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        Thread.sleep(5000);

        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        Long endTime = System.currentTimeMillis();
                        Request restRequest = new Request("GET", "/_plugins/_security_analytics/correlations?start_timestamp=" + startTime + "&end_timestamp=" + endTime);
                        Response restResponse = client().performRequest(restRequest);

                        Map<String, Object> responseMap = entityAsMap(restResponse);
                        List<Object> results = (List<Object>) responseMap.get("findings");
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

    public void testBasicCorrelationEngineWorkflowWithFieldBasedRulesOnMultipleLogTypes() throws IOException, InterruptedException {
        updateClusterSetting(SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS.getKey(), "false");

        LogIndices indices = new LogIndices();
        indices.windowsIndex = createTestIndex(randomIndex(), windowsIndexMapping());
        indices.vpcFlowsIndex = createTestIndex("vpc_flow", vpcFlowMappings());

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String testWindowsMonitorId = createTestWindowsDetector(indices.windowsIndex);

        String ruleId = createNetworkToWindowsFieldBasedRule(indices);

        indexDoc(indices.windowsIndex, "2", randomDoc());
        Response executeResponse = executeAlertingMonitor(testWindowsMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);

        indexDoc(indices.vpcFlowsIndex, "1", randomVpcFlowDoc());
        executeResponse = executeAlertingMonitor(vpcFlowMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
        Thread.sleep(5000);

        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", "test_windows");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        String finding = ((List<Map<String, Object>>) getFindingsBody.get("findings")).get(0).get("id").toString();

        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        List<Map<String, Object>> correlatedFindings = searchCorrelatedFindings(finding, "test_windows", 300000L, 10);
                        if (correlatedFindings.size() == 1) {
                            Assert.assertTrue(true);

                            Assert.assertTrue(correlatedFindings.get(0).get("rules") instanceof List);

                            for (var correlatedFinding: correlatedFindings) {
                                if (correlatedFinding.get("detector_type").equals("network")) {
                                    Assert.assertEquals(1, ((List<String>) correlatedFinding.get("rules")).size());
                                    Assert.assertTrue(((List<String>) correlatedFinding.get("rules")).contains(ruleId));
                                    return true;
                                }
                            }
                        }
                        return false;
                    } catch (Exception ex) {
                        return false;
                    }
                },
                2, TimeUnit.MINUTES
        );
    }

    // broken by https://github.com/opensearch-project/common-utils/pull/829
    @AwaitsFix(bugUrl = "https://github.com/opensearch-project/common-utils/pull/829")
    public  void testBasicCorrelationEngineWorkflowWithIndexPatterns() throws IOException, InterruptedException {
        updateClusterSetting(SecurityAnalyticsSettings.ENABLE_AUTO_CORRELATIONS.getKey(), "false");

        LogIndices indices = new LogIndices();
        createTestIndex("windows1", windowsIndexMapping());
        createTestIndex("windows2", windowsIndexMapping());
        indices.windowsIndex = "windows*";
        createTestIndex("vpc_flow1", vpcFlowMappings());
        createTestIndex("vpc_flow2", vpcFlowMappings());
        indices.vpcFlowsIndex = "vpc_flow*";

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String testWindowsMonitorId = createTestWindowsDetector(indices.windowsIndex);

        String ruleId = createNetworkToWindowsFilterQueryBasedRule(indices);

        indexDoc("windows2", "2", randomDoc());
        Response executeResponse = executeAlertingMonitor(testWindowsMonitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);

        indexDoc("vpc_flow1", "1", randomVpcFlowDoc());
        executeResponse = executeAlertingMonitor(vpcFlowMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
        Thread.sleep(5000);

        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", "test_windows");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        String finding = ((List<Map<String, Object>>) getFindingsBody.get("findings")).get(0).get("id").toString();

        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        List<Map<String, Object>> correlatedFindings = searchCorrelatedFindings(finding, "test_windows", 300000L, 10);
                        if (correlatedFindings.size() == 1) {
                            Assert.assertTrue(true);

                            Assert.assertTrue(correlatedFindings.get(0).get("rules") instanceof List);

                            for (var correlatedFinding: correlatedFindings) {
                                if (correlatedFinding.get("detector_type").equals("network")) {
                                    Assert.assertEquals(1, ((List<String>) correlatedFinding.get("rules")).size());
                                    Assert.assertTrue(((List<String>) correlatedFinding.get("rules")).contains(ruleId));
                                    return true;
                                }
                            }
                        }
                        return false;
                    } catch (Exception ex) {
                        return false;
                    }
                },
                2, TimeUnit.MINUTES
        );
    }

    public void testBasicCorrelationEngineWorkflowWithFieldBasedRulesAndDynamicTimeWindow() throws IOException, InterruptedException {
        Long startTime = System.currentTimeMillis();
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

        createCloudtrailFieldBasedRule(index, "requestParameters.userName", 5000L);

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
        Thread.sleep(30000);
        indexDoc(index, "4", randomCloudtrailDoc("deysubho", "CreateUser"));
        executeAlertingMonitor(monitorId, Collections.emptyMap());
        Thread.sleep(1000);

        indexDoc(index, "2", randomCloudtrailDoc("Richard", "DeleteUser"));
        executeAlertingMonitor(monitorId, Collections.emptyMap());

        // Call GetFindings API
        Map<String, String> params = new HashMap<>();
        params.put("detectorType", "cloudtrail");
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);

        Thread.sleep(5000);

        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        Long endTime = System.currentTimeMillis();
                        Request restRequest = new Request("GET", "/_plugins/_security_analytics/correlations?start_timestamp=" + startTime + "&end_timestamp=" + endTime);
                        Response response1 = client().performRequest(restRequest);

                        Map<String, Object> responseMap = entityAsMap(response1);
                        List<Object> results = (List<Object>) responseMap.get("findings");
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

    public void testBasicCorrelationEngineWorkflowWithCustomLogTypes() throws IOException, InterruptedException {
        LogIndices indices = new LogIndices();
        indices.vpcFlowsIndex = createTestIndex("vpc_flow1", vpcFlowMappings());

        String vpcFlowMonitorId = createVpcFlowDetector(indices.vpcFlowsIndex);
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        createdId = responseBody.get("_id").toString();

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", customLogType.getName(), detectorTypeInResponse);

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
        String ruleId = createNetworkToCustomLogTypeFieldBasedRule(indices, customLogType.getName(), index);

        indexDoc(index, "1", randomDoc());
        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);
        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        indexDoc(indices.vpcFlowsIndex, "1", randomVpcFlowDoc());
        executeResponse = executeAlertingMonitor(vpcFlowMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);
        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
        Thread.sleep(5000);

        Map<String, String> params = new HashMap<>();
        params.put("detectorType", customLogType.getName());
        Response getFindingsResponse = makeRequest(client(), "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
        Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
        String finding = ((List<Map<String, Object>>) getFindingsBody.get("findings")).get(0).get("id").toString();

        OpenSearchRestTestCase.waitUntil(
                () -> {
                    try {
                        List<Map<String, Object>> correlatedFindings = searchCorrelatedFindings(finding, customLogType.getName(), 300000L, 10);
                        if (correlatedFindings.size() == 1) {
                            Assert.assertTrue(true);

                            Assert.assertTrue(correlatedFindings.get(0).get("rules") instanceof List);

                            for (var correlatedFinding: correlatedFindings) {
                                if (correlatedFinding.get("detector_type").equals("network")) {
                                    Assert.assertEquals(1, ((List<String>) correlatedFinding.get("rules")).size());
                                    Assert.assertTrue(((List<String>) correlatedFinding.get("rules")).contains(ruleId));
                                    return true;
                                }
                            }
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