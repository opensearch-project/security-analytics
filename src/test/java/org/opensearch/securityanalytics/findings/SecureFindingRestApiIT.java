/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.findings;

import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
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

import static org.opensearch.securityanalytics.TestHelpers.netFlowMappings;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;

public class SecureFindingRestApiIT extends SecurityAnalyticsRestTestCase {

    static String SECURITY_ANALYTICS_FULL_ACCESS_ROLE = "security_analytics_full_access";
    static String SECURITY_ANALYTICS_READ_ACCESS_ROLE = "security_analytics_read_access";
    static String TEST_HR_BACKEND_ROLE = "HR";
    static String TEST_IT_BACKEND_ROLE = "IT";
    private final String user = "userFinding";
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
    public void testGetFindings_byDetectorId_success() throws IOException {
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

            Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
            Map<String, Object> executeResults = entityAsMap(executeResponse);

            int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
            Assert.assertEquals(5, noOfSigmaRuleMatches);

            // try to do get finding as a user with read access
            String userRead = "userReadFinding";
            String[] backendRoles = { TEST_IT_BACKEND_ROLE };
            createUserWithData( userRead, userRead, SECURITY_ANALYTICS_READ_ACCESS_ROLE, backendRoles );
            RestClient userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();
            // Call GetFindings API
            Map<String, String> params = new HashMap<>();
            params.put("detector_id", createdId);
            Response getFindingsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
            Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
            Assert.assertEquals(1, getFindingsBody.get("total_findings"));

            // Enable backend filtering and try to read finding as a user with no backend roles matching the user who created the detector
            enableOrDisableFilterBy("true");
            try {
                getFindingsResponse =  makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
            } catch (ResponseException e)
            {
                assertEquals("Get finding failed", RestStatus.FORBIDDEN, restStatus(e.getResponse()));
            }
            finally {
                userReadOnlyClient.close();
                deleteUser(userRead);
            }

            // recreate user with matching backend roles and try again
            String[] newBackendRoles = { TEST_HR_BACKEND_ROLE };
            createUserWithData( userRead, userRead, SECURITY_ANALYTICS_READ_ACCESS_ROLE, newBackendRoles );
            userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();
            getFindingsResponse =  makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
            getFindingsBody = entityAsMap(getFindingsResponse);
            Assert.assertEquals(1, getFindingsBody.get("total_findings"));
            userReadOnlyClient.close();

            // update user with no backend roles and try again
            createUser(userRead, userRead, EMPTY_ARRAY);
            userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();
            try {
                getFindingsResponse =  makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
            } catch (ResponseException e)
            {
                assertEquals("Get finding failed", RestStatus.FORBIDDEN, restStatus(e.getResponse()));
            }
            finally {
                userReadOnlyClient.close();
                deleteUser(userRead);
            }

        } finally {
            tryDeletingRole(TEST_HR_ROLE);
        }
    }

    public void testGetFindings_byDetectorType_success() throws IOException {
        try {
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
            Response response = userClient.performRequest(createMappingRequest);
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

            response = userClient.performRequest(createMappingRequest);
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

            createIndexRole(TEST_HR_ROLE, Collections.emptyList(), indexPermissions, List.of(index1, index2));
            String[] users = {user};
            createUserRolesMapping(TEST_HR_ROLE, users);

            // Detector 1 - WINDOWS
            Detector detector1 = randomDetectorWithTriggers(getRandomPrePackagedRules(), List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of())));
            Response createResponse = makeRequest(userClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector1));
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

            createResponse = makeRequest(userClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector2));
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


            // try to do get finding as a user with read access
            String userRead = "userReadFinding";
            String[] backendRoles = { TEST_IT_BACKEND_ROLE };
            createUserWithData( userRead, userRead, SECURITY_ANALYTICS_READ_ACCESS_ROLE, backendRoles );
            RestClient userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();


            // Call GetFindings API for first detector
            Map<String, String> params = new HashMap<>();
            params.put("detectorType", detector1.getDetectorType());
            Response getFindingsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
            Map<String, Object> getFindingsBody = entityAsMap(getFindingsResponse);
            Assert.assertEquals(1, getFindingsBody.get("total_findings"));
            // Call GetFindings API for second detector
            params.clear();
            params.put("detectorType", detector2.getDetectorType());
            getFindingsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
            getFindingsBody = entityAsMap(getFindingsResponse);
            Assert.assertEquals(1, getFindingsBody.get("total_findings"));

            // Enable backend filtering and try to read finding as a user with no backend roles matching the user who created the detector
            enableOrDisableFilterBy("true");
            try {
                getFindingsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
            } catch (ResponseException e)
            {
                assertEquals("Get finding failed", RestStatus.NOT_FOUND, restStatus(e.getResponse()));
            }
            finally {
                userReadOnlyClient.close();
                deleteUser(userRead);
            }

            // recreate user with matching backend roles and try again
            String[] newBackendRoles = { TEST_HR_BACKEND_ROLE };
            createUserWithData( userRead, userRead, SECURITY_ANALYTICS_READ_ACCESS_ROLE, newBackendRoles );
            userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();
            getFindingsResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
            getFindingsBody = entityAsMap(getFindingsResponse);
            Assert.assertEquals(1, getFindingsBody.get("total_findings"));
            userReadOnlyClient.close();


            // update user with no backend roles and try again
            createUser(userRead, userRead, EMPTY_ARRAY);
            userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();
            try {
                getFindingsResponse =  makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.FINDINGS_BASE_URI + "/_search", params, null);
            } catch (ResponseException e)
            {
                assertEquals("Get finding failed", RestStatus.FORBIDDEN, restStatus(e.getResponse()));
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
