/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resources;

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
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.model.Detector;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.opensearch.securityanalytics.TestHelpers.*;

public class ResourceSharingIT extends SecurityAnalyticsRestTestCase {

    private static final String SA_FULL_ACCESS_USER = "sa_full_access_user";
    private static final String SA_READ_ACCESS_USER = "sa_read_access_user";

    private static final String SA_FULL_ACCESS_ROLE = "sa_full_access_role";
    private static final String SA_READ_ACCESS_ROLE = "sa_read_access_role";

    private static final List<String> FULL_ACCESS_PERMISSIONS = List.of(
        "cluster:admin/opensearch/securityanalytics/detector/*",
        "cluster:admin/opensearch/securityanalytics/alerts/*",
        "cluster:admin/opensearch/securityanalytics/findings/*",
        "cluster:admin/opensearch/securityanalytics/mapping/*",
        "cluster:admin/opensearch/securityanalytics/rule/*",
        "cluster:admin/index/correlation/rules/*",
        "cluster:admin/opensearch/securityanalytics/correlation/rule/search",
        "cluster:admin/opensearch/securityanalytics/correlations/*",
        "cluster:admin/opensearch/securityanalytics/correlationAlerts/*",
        "cluster:admin/security/resource/share"
    );

    private static final List<String> READ_ACCESS_PERMISSIONS = List.of(
        "cluster:admin/opensearch/securityanalytics/detector/get",
        "cluster:admin/opensearch/securityanalytics/detector/search",
        "cluster:admin/opensearch/securityanalytics/alerts/get",
        "cluster:admin/opensearch/securityanalytics/findings/get",
        "cluster:admin/opensearch/securityanalytics/mapping/get",
        "cluster:admin/opensearch/securityanalytics/mapping/view/get",
        "cluster:admin/opensearch/securityanalytics/correlation/rule/search",
        "cluster:admin/opensearch/securityanalytics/correlations/list",
        "cluster:admin/opensearch/securityanalytics/correlations/findings",
        "cluster:admin/opensearch/securityanalytics/correlationAlerts/get"
    );

    private RestClient fullAccessClient;
    private RestClient readAccessClient;

    @Before
    public void setup() throws IOException {
        if (!isResourceSharingEnabled()) {
            return;
        }

        String[] emptyBackendRoles = {};
        createUserWithDataAndCustomRole(
            SA_FULL_ACCESS_USER, password, SA_FULL_ACCESS_ROLE,
            emptyBackendRoles, FULL_ACCESS_PERMISSIONS,
            List.of("indices:data/read/*", "indices:data/write/*", "indices:admin/mapping/put", "indices:admin/create"),
            List.of("*")
        );
        createUserWithDataAndCustomRole(
            SA_READ_ACCESS_USER, password, SA_READ_ACCESS_ROLE,
            emptyBackendRoles, READ_ACCESS_PERMISSIONS,
            List.of("indices:data/read/*"),
            List.of("*")
        );

        HttpHost[] hosts = getClusterHosts().toArray(new HttpHost[]{});
        fullAccessClient = new SecureRestClientBuilder(hosts, isHttps(), SA_FULL_ACCESS_USER, password)
            .setSocketTimeout(60000).build();
        readAccessClient = new SecureRestClientBuilder(hosts, isHttps(), SA_READ_ACCESS_USER, password)
            .setSocketTimeout(60000).build();
    }

    @After
    public void cleanup() throws IOException {
        if (!isResourceSharingEnabled()) {
            return;
        }
        if (fullAccessClient != null) fullAccessClient.close();
        if (readAccessClient != null) readAccessClient.close();
        deleteUser(SA_FULL_ACCESS_USER);
        deleteUser(SA_READ_ACCESS_USER);
    }

    public void testDetectorCRUDWithResourceSharing() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        String index = createTestIndex(client(), randomIndex(), windowsIndexMapping(), Settings.EMPTY);
        indexDoc(client(), index, "1", randomDoc(), true);

        // Create detector as full-access user
        Detector detector = randomDetector(getRandomPrePackagedRules());
        Response createResponse = makeRequest(fullAccessClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
            Collections.emptyMap(), toHttpEntity(detector));
        assertEquals(HttpStatus.SC_CREATED, createResponse.getStatusLine().getStatusCode());

        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();

        // Owner can GET
        Response getResponse = makeRequest(fullAccessClient, "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, getResponse.getStatusLine().getStatusCode());

        // Other user gets 403
        try {
            makeRequest(readAccessClient, "GET",
                SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
            fail("Expected 403 for unauthorized user");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_FORBIDDEN, e.getResponse().getStatusLine().getStatusCode());
        }

        // Share with read-only access
        shareResource(detectorId, Detector.DETECTORS_INDEX, "sa_read_only", SA_READ_ACCESS_USER);
        waitForSharingVisibility(readAccessClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // Now read-access user can GET
        Response sharedGetResponse = makeRequest(readAccessClient, "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, sharedGetResponse.getStatusLine().getStatusCode());

        // But read-access user cannot DELETE
        try {
            makeRequest(readAccessClient, "DELETE",
                SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
            fail("Expected 403 for read-only user on delete");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_FORBIDDEN, e.getResponse().getStatusLine().getStatusCode());
        }

        // Owner can DELETE
        Response deleteResponse = makeRequest(fullAccessClient, "DELETE",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, deleteResponse.getStatusLine().getStatusCode());
    }

    public void testDetectorSearchWithResourceSharing() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        String index = createTestIndex(client(), randomIndex(), windowsIndexMapping(), Settings.EMPTY);
        indexDoc(client(), index, "1", randomDoc(), true);

        // Create detector as full-access user
        Detector detector = randomDetector(getRandomPrePackagedRules());
        Response createResponse = makeRequest(fullAccessClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
            Collections.emptyMap(), toHttpEntity(detector));
        assertEquals(HttpStatus.SC_CREATED, createResponse.getStatusLine().getStatusCode());

        // Owner can find detector via search
        String searchBody = "{\"query\":{\"match_all\":{}}}";
        Response searchResponse = makeRequest(fullAccessClient, "POST",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/_search", Collections.emptyMap(),
            new StringEntity(searchBody), new org.apache.hc.core5.http.message.BasicHeader("Content-Type", "application/json"));
        Map<String, Object> searchResults = asMap(searchResponse);
        Map<String, Object> hits = (Map<String, Object>) searchResults.get("hits");
        Map<String, Object> total = (Map<String, Object>) hits.get("total");
        assertTrue(((Number) total.get("value")).intValue() > 0);

        // Read-access user sees nothing (not shared)
        Response readSearchResponse = makeRequest(readAccessClient, "POST",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/_search", Collections.emptyMap(),
            new StringEntity(searchBody), new org.apache.hc.core5.http.message.BasicHeader("Content-Type", "application/json"));
        Map<String, Object> readSearchResults = asMap(readSearchResponse);
        Map<String, Object> readHits = (Map<String, Object>) readSearchResults.get("hits");
        Map<String, Object> readTotal = (Map<String, Object>) readHits.get("total");
        assertEquals(0, ((Number) readTotal.get("value")).intValue());
    }

    public void testCorrelationRuleCRUDWithResourceSharing() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        // Create correlation rule as full-access user
        String correlationRuleBody = createCorrelationRuleBody();
        Response createResponse = makeRequest(fullAccessClient, "POST",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, Collections.emptyMap(),
            new StringEntity(correlationRuleBody), new org.apache.hc.core5.http.message.BasicHeader("Content-Type", "application/json"));
        assertEquals(HttpStatus.SC_CREATED, createResponse.getStatusLine().getStatusCode());

        Map<String, Object> responseBody = asMap(createResponse);
        String ruleId = responseBody.get("_id").toString();

        // Other user gets 403 on delete
        try {
            makeRequest(readAccessClient, "DELETE",
                SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/" + ruleId, Collections.emptyMap(), null);
            fail("Expected 403 for unauthorized user on delete");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_FORBIDDEN, e.getResponse().getStatusLine().getStatusCode());
        }

        // Owner can delete
        Response deleteResponse = makeRequest(fullAccessClient, "DELETE",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/" + ruleId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, deleteResponse.getStatusLine().getStatusCode());
    }

    public void testCorrelationRuleSearchWithResourceSharing() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        // Create correlation rule as full-access user
        String correlationRuleBody = createCorrelationRuleBody();
        Response createResponse = makeRequest(fullAccessClient, "POST",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, Collections.emptyMap(),
            new StringEntity(correlationRuleBody), new org.apache.hc.core5.http.message.BasicHeader("Content-Type", "application/json"));
        assertEquals(HttpStatus.SC_CREATED, createResponse.getStatusLine().getStatusCode());

        // Owner can find it
        String searchBody = "{\"query\":{\"match_all\":{}}}";
        Response searchResponse = makeRequest(fullAccessClient, "POST",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", Collections.emptyMap(),
            new StringEntity(searchBody), new org.apache.hc.core5.http.message.BasicHeader("Content-Type", "application/json"));
        Map<String, Object> searchResults = asMap(searchResponse);
        Map<String, Object> hits = (Map<String, Object>) searchResults.get("hits");
        Map<String, Object> total = (Map<String, Object>) hits.get("total");
        assertTrue(((Number) total.get("value")).intValue() > 0);

        // Read-access user sees nothing (not shared)
        Response readSearchResponse = makeRequest(readAccessClient, "POST",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", Collections.emptyMap(),
            new StringEntity(searchBody), new org.apache.hc.core5.http.message.BasicHeader("Content-Type", "application/json"));
        Map<String, Object> readSearchResults = asMap(readSearchResponse);
        Map<String, Object> readHits = (Map<String, Object>) readSearchResults.get("hits");
        Map<String, Object> readTotal = (Map<String, Object>) readHits.get("total");
        assertEquals(0, ((Number) readTotal.get("value")).intValue());
    }

    // --- Helper methods ---

    private boolean isResourceSharingEnabled() {
        return "true".equals(System.getProperty("resource_sharing.enabled"));
    }

    private void shareResource(String resourceId, String resourceIndex, String accessLevel, String shareWithUser) throws IOException {
        String endpoint = String.format(Locale.ROOT, "/_plugins/_security/api/resource/%s/%s/share", resourceIndex, resourceId);
        String body = String.format(Locale.ROOT,
            "{\"share_with\":{\"%s\":{\"users\":[\"%s\"]}}}",
            accessLevel, shareWithUser);
        Request request = new Request("PUT", endpoint);
        request.setJsonEntity(body);
        client().performRequest(request);
    }

    private void waitForSharingVisibility(RestClient userClient, String resourceEndpoint) throws Exception {
        int maxRetries = 30;
        for (int i = 0; i < maxRetries; i++) {
            try {
                Response response = makeRequest(userClient, "GET", resourceEndpoint, Collections.emptyMap(), null);
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    return;
                }
            } catch (ResponseException e) {
                if (e.getResponse().getStatusLine().getStatusCode() != HttpStatus.SC_FORBIDDEN) {
                    throw e;
                }
            }
            Thread.sleep(200);
        }
        fail("Resource did not become visible within timeout");
    }

    private String createCorrelationRuleBody() {
        return "{"
            + "\"name\": \"test-corr-rule\","
            + "\"correlate\": ["
            + "  {\"index\": \"index-1\", \"query\": \"host.hostname:EC2*\", \"category\": \"windows\"},"
            + "  {\"index\": \"index-2\", \"query\": \"host.hostname:EC2*\", \"category\": \"network\"}"
            + "]"
            + "}";
    }
}
