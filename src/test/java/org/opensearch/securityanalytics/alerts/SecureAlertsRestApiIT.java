/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;


import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.TestHelpers.*;

public class SecureAlertsRestApiIT extends SecurityAnalyticsRestTestCase {

    static String SECURITY_ANALYTICS_FULL_ACCESS_ROLE = "security_analytics_full_access";
    static String SECURITY_ANALYTICS_READ_ACCESS_ROLE = "security_analytics_read_access";
    static String TEST_HR_BACKEND_ROLE = "HR";
    static String TEST_IT_BACKEND_ROLE = "IT";
    private final String user = "userAlert";
    private static final String[] EMPTY_ARRAY = new String[0];
    private RestClient userClient;

    @Before
    public void create() throws IOException {
        String[] backendRoles = { TEST_HR_BACKEND_ROLE };
        createUserWithData(user, user, SECURITY_ANALYTICS_FULL_ACCESS_ROLE, backendRoles );
        if (userClient == null) {
            userClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), user, user).setSocketTimeout(60000).build();
        }
    }

    @After
    public void cleanup() throws IOException {
        userClient.close();
        deleteUser(user);
    }

    @SuppressWarnings("unchecked")
    public void testGetAlerts_byDetectorId_success() throws IOException {
        try {
            String index = createTestIndex(randomIndex(), windowsIndexMapping());
            // Assign a role to the index
            createIndexRole(TEST_HR_ROLE, Collections.emptyList(), indexPermissions, List.of(index));
            String[] users = {user};
            // Assign a role to existing user
            createUserRolesMapping(TEST_HR_ROLE, users);

            String rule = randomRule();

            Response createResponse = makeRequest(userClient, "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
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

            Response response = userClient.performRequest(createMappingRequest);
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

            createAlertingMonitorConfigIndex(null);
            Action triggerAction = randomAction(createDestination());

            Detector detector = randomDetectorWithInputsAndTriggers(List.of(new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(createdId)),
                    getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(), List.of(createdId), List.of(), List.of("attack.defense_evasion"), List.of(triggerAction))));

            createResponse = makeRequest(userClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
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

            // try to do get finding as a user with read access
            String userRead = "userReadAlert";
            String[] backendRoles = { TEST_IT_BACKEND_ROLE };
            createUserWithData( userRead, userRead, SECURITY_ANALYTICS_READ_ACCESS_ROLE, backendRoles );
            RestClient userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();

            // Call GetAlerts API
            Map<String, String> params = new HashMap<>();
            params.put("detector_id", createdId);
            Response getAlertsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
            Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
            Assert.assertEquals(1, getAlertsBody.get("total_alerts"));

            // Enable backend filtering and try to read finding as a user with no backend roles matching the user who created the detector
            enableOrDisableFilterBy("true");
            try {
                getAlertsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
            } catch (ResponseException e)
            {
                assertEquals("Get alert failed", RestStatus.FORBIDDEN, restStatus(e.getResponse()));
            }
            finally {
                userReadOnlyClient.close();
                deleteUser(userRead);
            }

            // recreate user with matching backend roles and try again
            String[] newBackendRoles = { TEST_HR_BACKEND_ROLE };
            createUserWithData( userRead, userRead, SECURITY_ANALYTICS_READ_ACCESS_ROLE, newBackendRoles );
            userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();
            getAlertsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
            getAlertsBody = asMap(getAlertsResponse);
            Assert.assertEquals(1, getAlertsBody.get("total_alerts"));
            userReadOnlyClient.close();

            // update user with no backend roles and try again
            createUser(userRead, userRead, EMPTY_ARRAY);
            userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();
            try {
                getAlertsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
            } catch (ResponseException e)
            {
                assertEquals("Get alert failed", RestStatus.FORBIDDEN, restStatus(e.getResponse()));
            }
            finally {
                userReadOnlyClient.close();
                deleteUser(userRead);
            }
        } finally {
            tryDeletingRole(TEST_HR_ROLE);
        }

    }


    public void testGetAlerts_byDetectorType_success() throws IOException, InterruptedException {
        try {
            String index = createTestIndex(randomIndex(), windowsIndexMapping());
            // Assign a role to the index
            createIndexRole(TEST_HR_ROLE, Collections.emptyList(), indexPermissions, List.of(index));
            String[] users = {user};
            // Assign a role to existing user
            createUserRolesMapping(TEST_HR_ROLE, users);

            // Execute CreateMappingsAction to add alias mapping for index
            Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
            // both req params and req body are supported
            createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                    "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                    "  \"partial\":true" +
                    "}"
            );

            Response response = userClient.performRequest(createMappingRequest);
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

            Detector detector = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));

            Response createResponse = makeRequest(userClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
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
                hits = executeSearch(DetectorMonitorConfig.getAlertsIndex(randomDetectorType()), request);
            }

            // try to do get finding as a user with read access
            String userRead = "userReadAlert";
            String[] backendRoles = { TEST_IT_BACKEND_ROLE };
            createUserWithData( userRead, userRead, SECURITY_ANALYTICS_READ_ACCESS_ROLE, backendRoles );
            RestClient userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();

            // Call GetAlerts API
            Map<String, String> params = new HashMap<>();
            params.put("detectorType", randomDetectorType());
            Response getAlertsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
            Map<String, Object> getAlertsBody = asMap(getAlertsResponse);
            Assert.assertEquals(1, getAlertsBody.get("total_alerts"));

            // Enable backend filtering and try to read finding as a user with no backend roles matching the user who created the detector
            enableOrDisableFilterBy("true");
            try {
                getAlertsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
            } catch (ResponseException e)
            {
                assertEquals("Get alert failed", RestStatus.NOT_FOUND, restStatus(e.getResponse()));
            }
            finally {
                userReadOnlyClient.close();
                deleteUser(userRead);
            }

            // recreate user with matching backend roles and try again
            String[] newBackendRoles = { TEST_HR_BACKEND_ROLE };
            createUserWithData( userRead, userRead, SECURITY_ANALYTICS_READ_ACCESS_ROLE, newBackendRoles );
            userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();
            getAlertsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
            getAlertsBody = asMap(getAlertsResponse);
            Assert.assertEquals(1, getAlertsBody.get("total_alerts"));
            userReadOnlyClient.close();

            // update user with no backend roles and try again
            createUser(userRead, userRead, EMPTY_ARRAY);
            userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();
            try {
                getAlertsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.ALERTS_BASE_URI, params, null);
            } catch (ResponseException e)
            {
                assertEquals("Get alert failed", RestStatus.FORBIDDEN, restStatus(e.getResponse()));
            }
            finally {
                userReadOnlyClient.close();
                deleteUser(userRead);
            }
        } finally {
            tryDeletingRole(TEST_HR_ROLE);
        }
    }

}