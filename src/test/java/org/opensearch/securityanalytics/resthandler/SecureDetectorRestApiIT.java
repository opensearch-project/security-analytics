/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpStatus;
import org.apache.http.entity.ContentType;
import org.apache.http.nio.entity.NStringEntity;
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
    static String CUSTOM_HR_ROLE = "HR";

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
        String[] users = {user};
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
//        String queryJson = "{ \"query\": { \"match_all\": { } } }";
//
        HttpEntity requestEntity = new NStringEntity(queryJson, ContentType.APPLICATION_JSON);
        Response searchResponse = makeRequest(userReadOnlyClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + "_search", Collections.emptyMap(), requestEntity);
        Map<String, Object> searchResponseBody = asMap(searchResponse);
        Assert.assertNotNull("response is not null", searchResponseBody);
        Map<String, Object> searchResponseHits = (Map) searchResponseBody.get("hits");
        Map<String, Object> searchResponseTotal = (Map) searchResponseHits.get("total");
        Assert.assertEquals(1, searchResponseTotal.get("value"));

        userReadOnlyClient.close();
        deleteUser(userRead);
    }
}