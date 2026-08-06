/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpStatus;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.junit.After;
import org.junit.Before;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;

import java.io.IOException;
import java.util.Collections;

/**
 * Tests that verify the authorization bypass fixes in the security-analytics plugin.
 * These tests confirm that:
 * 1. Users without index permissions cannot read/write arbitrary indices via plugin endpoints
 * 2. Terms lookup queries referencing external indices are blocked
 * 3. Normal operations for authorized users still work
 */
public class SecureMappingsAndSearchRestApiIT extends SecurityAnalyticsRestTestCase {

    static String SECURITY_ANALYTICS_READ_ACCESS_ROLE = "security_analytics_read_access";

    private static final String SENSITIVE_INDEX = "hr-salaries-test";
    private static final String SENSITIVE_INDEX_MAPPING =
            "\"properties\": {" +
            "  \"employee_name\": { \"type\": \"text\" }," +
            "  \"employee_national_id\": { \"type\": \"keyword\" }," +
            "  \"base_salary_usd\": { \"type\": \"integer\" }" +
            "}";

    private RestClient readOnlyClient;
    private final String readOnlyUser = "analyst_read_only";

    @Before
    public void setup() throws IOException {
        if (!securityEnabled()) return;

        createTestIndex(client(), SENSITIVE_INDEX, SENSITIVE_INDEX_MAPPING, Settings.EMPTY);
        indexDoc(client(), SENSITIVE_INDEX, "1",
                "{\"employee_name\": \"Alice\", \"employee_national_id\": \"123-45-6789\", \"base_salary_usd\": 150000}",
                true);

        String[] backendRoles = {"ANALYST"};
        createUserWithData(readOnlyUser, readOnlyUser, SECURITY_ANALYTICS_READ_ACCESS_ROLE, backendRoles);
        readOnlyClient = new SecureRestClientBuilder(
                getClusterHosts().toArray(new HttpHost[]{}), isHttps(), readOnlyUser, password
        ).setSocketTimeout(60000).build();
    }

    @After
    public void cleanup() throws IOException {
        if (!securityEnabled()) return;
        if (readOnlyClient != null) readOnlyClient.close();
        deleteUser(readOnlyUser);
    }

    public void testMappingsViewRejectsUnauthorizedIndex() throws IOException {
        if (!securityEnabled()) return;

        try {
            readOnlyClient.performRequest(new Request("GET",
                    SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI +
                    "?index_name=" + SENSITIVE_INDEX + "&rule_topic=windows"));
            fail("Expected 403 for unauthorized index access via mappings/view");
        } catch (ResponseException e) {
            assertEquals(RestStatus.FORBIDDEN.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        }
    }

    public void testGetMappingsRejectsUnauthorizedIndex() throws IOException {
        if (!securityEnabled()) return;

        try {
            readOnlyClient.performRequest(new Request("GET",
                    SecurityAnalyticsPlugin.MAPPER_BASE_URI + "?index_name=" + SENSITIVE_INDEX));
            fail("Expected 403 for unauthorized index access via GET mappings");
        } catch (ResponseException e) {
            assertEquals(RestStatus.FORBIDDEN.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        }
    }

    public void testDetectorSearchBlocksTermsLookup() throws IOException {
        if (!securityEnabled()) return;

        String termsLookupQuery = "{" +
                "\"size\": 0," +
                "\"query\": {" +
                "  \"terms\": {" +
                "    \"detector.name\": {" +
                "      \"index\": \"" + SENSITIVE_INDEX + "\"," +
                "      \"id\": \"1\"," +
                "      \"path\": \"employee_national_id\"" +
                "    }" +
                "  }" +
                "}" +
                "}";

        HttpEntity entity = new StringEntity(termsLookupQuery, ContentType.APPLICATION_JSON);
        try {
            makeRequest(readOnlyClient, "POST",
                    SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/_search",
                    Collections.emptyMap(), entity);
            fail("Expected 403 for terms lookup referencing external index");
        } catch (ResponseException e) {
            assertEquals(RestStatus.FORBIDDEN.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        }
    }

    public void testDetectorSearchAllowsInlineTerms() throws IOException {
        if (!securityEnabled()) return;

        String inlineTermsQuery = "{" +
                "\"size\": 0," +
                "\"query\": {" +
                "  \"terms\": {" +
                "    \"detector.name\": [\"test-1\", \"test-2\"]" +
                "  }" +
                "}" +
                "}";

        HttpEntity entity = new StringEntity(inlineTermsQuery, ContentType.APPLICATION_JSON);
        Response response = makeRequest(readOnlyClient, "POST",
                SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/_search",
                Collections.emptyMap(), entity);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    public void testDetectorSearchAllowsMatchAll() throws IOException {
        if (!securityEnabled()) return;

        String query = "{\"size\": 0, \"query\": {\"match_all\": {}}}";
        HttpEntity entity = new StringEntity(query, ContentType.APPLICATION_JSON);
        Response response = makeRequest(readOnlyClient, "POST",
                SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/_search",
                Collections.emptyMap(), entity);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    public void testRuleSearchBlocksTermsLookup() throws IOException {
        if (!securityEnabled()) return;

        String termsLookupQuery = "{" +
                "\"size\": 0," +
                "\"query\": {" +
                "  \"terms\": {" +
                "    \"rule.title\": {" +
                "      \"index\": \"" + SENSITIVE_INDEX + "\"," +
                "      \"id\": \"1\"," +
                "      \"path\": \"employee_national_id\"" +
                "    }" +
                "  }" +
                "}" +
                "}";

        HttpEntity entity = new StringEntity(termsLookupQuery, ContentType.APPLICATION_JSON);
        try {
            makeRequest(readOnlyClient, "POST",
                    SecurityAnalyticsPlugin.RULE_BASE_URI + "/_search?pre_packaged=true",
                    Collections.emptyMap(), entity);
            fail("Expected 403 for terms lookup in rule search");
        } catch (ResponseException e) {
            assertEquals(RestStatus.FORBIDDEN.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        }
    }

    public void testLogTypeSearchBlocksTermsLookup() throws IOException {
        if (!securityEnabled()) return;

        String termsLookupQuery = "{" +
                "\"size\": 0," +
                "\"query\": {" +
                "  \"terms\": {" +
                "    \"name\": {" +
                "      \"index\": \"" + SENSITIVE_INDEX + "\"," +
                "      \"id\": \"1\"," +
                "      \"path\": \"employee_national_id\"" +
                "    }" +
                "  }" +
                "}" +
                "}";

        HttpEntity entity = new StringEntity(termsLookupQuery, ContentType.APPLICATION_JSON);
        try {
            makeRequest(readOnlyClient, "POST",
                    SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/_search",
                    Collections.emptyMap(), entity);
            fail("Expected 403 for terms lookup in log type search");
        } catch (ResponseException e) {
            assertEquals(RestStatus.FORBIDDEN.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        }
    }

    public void testCreateMappingsRejectsUnauthorizedIndex() throws IOException {
        if (!securityEnabled()) return;

        // Create a custom role with only cluster permission, no index permissions
        createCustomRole("mapping_cluster_only",
                "cluster:admin/opensearch/securityanalytics/mapping/*");
        String customUser = "mapping_cluster_user";
        String[] backendRoles = {"ANALYST"};
        createUser(customUser, backendRoles);
        createUserRolesMapping("mapping_cluster_only", new String[]{customUser});

        RestClient customClient = new SecureRestClientBuilder(
                getClusterHosts().toArray(new HttpHost[]{}), isHttps(), customUser, password
        ).setSocketTimeout(60000).build();

        try {
            Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
            request.setJsonEntity("{\"index_name\": \"" + SENSITIVE_INDEX + "\", " +
                    "\"rule_topic\": \"windows\", \"partial\": true}");
            customClient.performRequest(request);
            fail("Expected 403 for POST mappings without index permissions");
        } catch (ResponseException e) {
            assertEquals(RestStatus.FORBIDDEN.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        } finally {
            customClient.close();
            deleteUser(customUser);
            tryDeletingRole("mapping_cluster_only");
        }
    }

    public void testUpdateMappingsRejectsUnauthorizedIndex() throws IOException {
        if (!securityEnabled()) return;

        // First create mappings as admin
        Request adminRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        adminRequest.setJsonEntity("{\"index_name\": \"" + SENSITIVE_INDEX + "\", " +
                "\"rule_topic\": \"windows\", \"partial\": true}");
        client().performRequest(adminRequest);

        // Create a custom role with only cluster permission
        createCustomRole("mapping_cluster_only2",
                "cluster:admin/opensearch/securityanalytics/mapping/*");
        String customUser = "mapping_cluster_user2";
        String[] backendRoles = {"ANALYST"};
        createUser(customUser, backendRoles);
        createUserRolesMapping("mapping_cluster_only2", new String[]{customUser});

        RestClient customClient = new SecureRestClientBuilder(
                getClusterHosts().toArray(new HttpHost[]{}), isHttps(), customUser, password
        ).setSocketTimeout(60000).build();

        try {
            Request request = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
            request.setJsonEntity("{\"index_name\": \"" + SENSITIVE_INDEX + "\", " +
                    "\"field\": \"employee_name\", \"alias\": \"winlog.event_data.SubjectUserName\"}");
            customClient.performRequest(request);
            fail("Expected 403 for PUT mappings without index permissions");
        } catch (ResponseException e) {
            assertEquals(RestStatus.FORBIDDEN.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        } finally {
            customClient.close();
            deleteUser(customUser);
            tryDeletingRole("mapping_cluster_only2");
        }
    }

    public void testMappingsViewWorksForAuthorizedUser() throws IOException {
        if (!securityEnabled()) return;

        // Admin should be able to use mappings/view
        Request request = new Request("GET",
                SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI +
                "?index_name=" + SENSITIVE_INDEX + "&rule_topic=windows");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    public void testGetMappingsWorksForAuthorizedUser() throws IOException {
        if (!securityEnabled()) return;

        Request request = new Request("GET",
                SecurityAnalyticsPlugin.MAPPER_BASE_URI + "?index_name=" + SENSITIVE_INDEX);
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    private Response indexDoc(RestClient client, String index, String id, String doc, boolean refresh) throws IOException {
        Request request = new Request("PUT", "/" + index + "/_doc/" + id + (refresh ? "?refresh=true" : ""));
        request.setJsonEntity(doc);
        return client.performRequest(request);
    }
}
