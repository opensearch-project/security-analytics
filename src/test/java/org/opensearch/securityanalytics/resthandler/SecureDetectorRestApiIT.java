/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.After;
import org.junit.Before;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.junit.Assert;
import org.opensearch.securityanalytics.model.Detector;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.io.IOException;

import static org.opensearch.securityanalytics.TestHelpers.*;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;

public class SecureDetectorRestApiIT extends SecurityAnalyticsRestTestCase {

    static String SECURITY_ANALYTICS_FULL_ACCESS_ROLE = "security_analytics_full_access";
    static String SECURITY_ANALYTICS_READ_ACCESS_ROLE = "security_analytics_read_access";
    static String TEST_HR_BACKEND_ROLE = "HR";

    static String TEST_IT_BACKEND_ROLE = "IT";

    static Map<String, String> roleToPermissionsMap = Map.ofEntries(
            Map.entry(SECURITY_ANALYTICS_FULL_ACCESS_ROLE, "cluster:admin/opendistro/securityanalytics/detector/*"),
            Map.entry(SECURITY_ANALYTICS_READ_ACCESS_ROLE, "cluster:admin/opendistro/securityanalytics/detector/read")
    );

    private RestClient userClient;
    private final String user = "userDetector";


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
    public void testCreateDetectorWithFullAccess() throws IOException {
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

            Detector detector = randomDetector(getRandomPrePackagedRules());

            Response createResponse = makeRequest(userClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
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

            // try to do get detector as a user with read access
            String userRead = "userRead";
            String[] backendRoles = { TEST_IT_BACKEND_ROLE };
            createUserWithData( userRead, userRead, SECURITY_ANALYTICS_READ_ACCESS_ROLE, backendRoles );
            RestClient userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();
            Response getResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
            Map<String, Object> getResponseBody = asMap(getResponse);
            Assert.assertEquals(createdId, getResponseBody.get("_id"));


            // Enable backend filtering and try to read detector as a user with no backend roles matching the user who created the detector
            enableOrDisableFilterBy("true");
            try {
                getResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
            } catch (ResponseException e)
            {
                assertEquals("Get detector failed", RestStatus.FORBIDDEN, restStatus(e.getResponse()));
            }
            finally {
                userReadOnlyClient.close();
                deleteUser(userRead);
            }

            // recreate user with matching backend roles and try again
            String[] newBackendRoles = { TEST_HR_BACKEND_ROLE };
            createUserWithData( userRead, userRead, SECURITY_ANALYTICS_READ_ACCESS_ROLE, newBackendRoles );
            userReadOnlyClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userRead, userRead).setSocketTimeout(60000).build();
            getResponse = makeRequest(userReadOnlyClient, "GET", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
            getResponseBody = asMap(getResponse);
            Assert.assertEquals(createdId, getResponseBody.get("_id"));

        //Search on id should give one result
            String queryJson = "{ \"query\": { \"match\": { \"_id\" : \"" + createdId + "\"} } }";
            HttpEntity requestEntity = new StringEntity(queryJson, ContentType.APPLICATION_JSON);
            Response searchResponse = makeRequest(userReadOnlyClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + "_search", Collections.emptyMap(), requestEntity);
            Map<String, Object> searchResponseBody = asMap(searchResponse);
            Assert.assertNotNull("response is not null", searchResponseBody);
            Map<String, Object> searchResponseHits = (Map) searchResponseBody.get("hits");
            Map<String, Object> searchResponseTotal = (Map) searchResponseHits.get("total");
            Assert.assertEquals(1, searchResponseTotal.get("value"));

            userReadOnlyClient.close();
            deleteUser(userRead);
        }  finally {
            tryDeletingRole(TEST_HR_ROLE);
        }
    }

    public void testCreateDetectorWithNoBackendRoles() throws IOException {
        // try to do create detector as a user with no backend roles
        String userFull= "userFull";
        String[] backendRoles = {};
        createUserWithData( userFull, userFull, SECURITY_ANALYTICS_FULL_ACCESS_ROLE, backendRoles );
        RestClient userFullClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userFull, userFull).setSocketTimeout(60000).build();

        String index = createTestIndex(client(), randomIndex(), windowsIndexMapping(), Settings.EMPTY);

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = userFullClient.performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetector(getRandomPrePackagedRules());
        // Enable backend filtering and try to read detector as a user with no backend roles matching the user who created the detector
        enableOrDisableFilterBy("true");
        try {
            Response createResponse = makeRequest(userFullClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        } catch (ResponseException e)
        {
            assertEquals("Create detector failed", RestStatus.FORBIDDEN, restStatus(e.getResponse()));
        }
        finally {
            userFullClient.close();
            deleteUser(userFull);
        }
    }

    public void testCreateDetector_userHasIndexAccess_success() throws IOException {
        String[] backendRoles = { TEST_IT_BACKEND_ROLE };
        String userWithAccess = "user1";
        String roleNameWithIndexPatternAccess = "test-role-1";
        String windowsIndexPattern = "windows*";
        createUserWithDataAndCustomRole(userWithAccess, userWithAccess, roleNameWithIndexPatternAccess, backendRoles, clusterPermissions, indexPermissions, List.of(windowsIndexPattern));
        RestClient clientWithAccess = null;

        try {
            clientWithAccess = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userWithAccess, userWithAccess).setSocketTimeout(60000).build();
            String index = createTestIndex(client(), randomIndex(), windowsIndexMapping(), Settings.EMPTY);

            Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
            createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                    "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                    "  \"partial\":true" +
                    "}"
            );
            Response response = clientWithAccess.performRequest(createMappingRequest);
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

            Detector detector = randomDetector(getRandomPrePackagedRules());

            Response createResponse = makeRequest(clientWithAccess, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
            assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

            Map<String, Object> responseBody = asMap(createResponse);

            String createdId = responseBody.get("_id").toString();
            int createdVersion = Integer.parseInt(responseBody.get("_version").toString());

            assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
            assertTrue("incorrect version", createdVersion > 0);
            assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
            assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
            assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
            assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));
        } finally {
            if (clientWithAccess != null) clientWithAccess.close();
            deleteUser(userWithAccess);
            tryDeletingRole(roleNameWithIndexPatternAccess);
        }
    }

    public void testCreateDetector_userDoesntHaveIndexAccess_failure() throws IOException {
        String[] backendRoles = { TEST_IT_BACKEND_ROLE };

        String userWithoutAccess = "user";
        String roleNameWithoutIndexPatternAccess = "test-role";
        String testIndexPattern = "test*";
        createUserWithDataAndCustomRole(userWithoutAccess, userWithoutAccess, roleNameWithoutIndexPatternAccess, backendRoles, clusterPermissions, indexPermissions, List.of(testIndexPattern));
        RestClient clientWithoutAccess = null;

        try {
            clientWithoutAccess =  new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userWithoutAccess, userWithoutAccess).setSocketTimeout(60000).build();

            String index = createTestIndex(client(), randomIndex(), windowsIndexMapping(), Settings.EMPTY);

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

            Detector detector = randomDetector(getRandomPrePackagedRules());

            try {
                makeRequest(clientWithoutAccess, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
            } catch (ResponseException e) {
                assertEquals("Create detector error status", RestStatus.FORBIDDEN, restStatus(e.getResponse()));
            }
        } finally {
            if (clientWithoutAccess!= null) clientWithoutAccess.close();
            deleteUser(userWithoutAccess);
            tryDeletingRole(roleNameWithoutIndexPatternAccess);
        }
    }

    public void testUpdateDetector_userHasIndexAccess_success() throws IOException {
        String[] backendRoles = { TEST_IT_BACKEND_ROLE };

        String userWithAccess = "user1";
        String roleNameWithIndexPatternAccess = "test-role-1";
        String windowsIndexPattern = "windows*";
        createUserWithDataAndCustomRole(userWithAccess, userWithAccess, roleNameWithIndexPatternAccess, backendRoles, clusterPermissions, indexPermissions, List.of(windowsIndexPattern));
        RestClient clientWithAccess =  null;
        try {
            clientWithAccess = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userWithAccess, userWithAccess).setSocketTimeout(60000).build();
            //createUserRolesMapping("alerting_full_access", users);
            String index = createTestIndex(client(), randomIndex(), windowsIndexMapping(), Settings.EMPTY);

            // Execute CreateMappingsAction to add alias mapping for index
            Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
            // both req params and req body are supported
            createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                    "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                    "  \"partial\":true" +
                    "}"
            );
            Response response = clientWithAccess.performRequest(createMappingRequest);
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

            Detector detector = randomDetector(getRandomPrePackagedRules());

            Response createResponse = makeRequest(clientWithAccess, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
            assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

            Map<String, Object> responseBody = asMap(createResponse);

            String createdId = responseBody.get("_id").toString();
            int createdVersion = Integer.parseInt(responseBody.get("_version").toString());

            assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
            assertTrue("incorrect version", createdVersion > 0);
            assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
            assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
            assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
            assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

            String detectorId = responseBody.get("_id").toString();
            Response updateResponse = makeRequest(clientWithAccess, "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(detector));
            assertEquals("Update detector failed", RestStatus.OK, restStatus(updateResponse));
        } finally {
            if (clientWithAccess != null) clientWithAccess.close();
            deleteUser(userWithAccess);
            tryDeletingRole(roleNameWithIndexPatternAccess);
        }
    }

    public void testUpdateDetector_userDoesntHaveIndexAccess_failure() throws IOException {
        String[] backendRoles = { TEST_IT_BACKEND_ROLE };

        String userWithoutAccess = "user";
        String roleNameWithoutIndexPatternAccess = "test-role";
        String testIndexPattern = "test*";
        createUserWithDataAndCustomRole(userWithoutAccess, userWithoutAccess, roleNameWithoutIndexPatternAccess, backendRoles, clusterPermissions, indexPermissions, List.of(testIndexPattern));
        RestClient clientWithoutAccess = null;

        try {
            clientWithoutAccess = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userWithoutAccess, userWithoutAccess).setSocketTimeout(60000).build();

            //createUserRolesMapping("alerting_full_access", users);
            String index = createTestIndex(client(), randomIndex(), windowsIndexMapping(), Settings.EMPTY);
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

            Detector detector = randomDetector(getRandomPrePackagedRules());

            Response createResponse = makeRequest(userClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
            assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

            Map<String, Object> responseBody = asMap(createResponse);

            String createdId = responseBody.get("_id").toString();
            int createdVersion = Integer.parseInt(responseBody.get("_version").toString());

            assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
            assertTrue("incorrect version", createdVersion > 0);
            assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
            assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
            assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
            assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

            String detectorId = responseBody.get("_id").toString();

            try {
                makeRequest(clientWithoutAccess, "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), toHttpEntity(detector));
            } catch (ResponseException e) {
                assertEquals("Update detector error status", RestStatus.FORBIDDEN, restStatus(e.getResponse()));
            }
        } finally {
            if (clientWithoutAccess != null) clientWithoutAccess.close();
            deleteUser(userWithoutAccess);
            tryDeletingRole(roleNameWithoutIndexPatternAccess);
            tryDeletingRole(TEST_HR_ROLE);
        }
    }
}