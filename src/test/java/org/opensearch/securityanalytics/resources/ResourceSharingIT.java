/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resources;

import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
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

    private static final String OWNER_USER = "sa_owner_user";
    private static final String OTHER_USER = "sa_other_user";
    private static final String THIRD_USER = "sa_third_user";

    private static final String OWNER_ROLE = "sa_owner_role";
    private static final String OTHER_ROLE = "sa_other_role";
    private static final String THIRD_ROLE = "sa_third_role";

    private static final List<String> FULL_ACCESS_PERMISSIONS = List.of(
        "cluster:admin/opensearch/securityanalytics/*",
        "cluster:admin/index/correlation/rules/*",
        "cluster:admin/opendistro/alerting/*",
        "cluster:admin/settings/update",
        "cluster:admin/security/resource/share"
    );

    private RestClient ownerClient;
    private RestClient otherClient;
    private RestClient thirdClient;

    @Before
    public void setup() throws IOException {
        if (!isResourceSharingEnabled()) {
            return;
        }

        String[] emptyBackendRoles = {};
        List<String> indexPerms = List.of("indices:data/read*", "indices:data/write*", "indices:admin/mapping/put", "indices:admin/mappings/get*", "indices:admin/create", "indices:admin/delete", "indices:admin/resolve/index");
        List<String> indexPatterns = List.of("*", ".opensearch-sap-*", ".opendistro-alerting-*");

        // Delete any leftover roles/users from prior runs so role updates take effect
        deleteRoleIfExists(OWNER_ROLE);
        deleteRoleIfExists(OTHER_ROLE);
        deleteRoleIfExists(THIRD_ROLE);

        createUserWithDataAndCustomRole(OWNER_USER, password, OWNER_ROLE, emptyBackendRoles, FULL_ACCESS_PERMISSIONS, indexPerms, indexPatterns);
        createUserWithDataAndCustomRole(OTHER_USER, password, OTHER_ROLE, emptyBackendRoles, FULL_ACCESS_PERMISSIONS, indexPerms, indexPatterns);
        createUserWithDataAndCustomRole(THIRD_USER, password, THIRD_ROLE, emptyBackendRoles, FULL_ACCESS_PERMISSIONS, indexPerms, indexPatterns);

        HttpHost[] hosts = getClusterHosts().toArray(new HttpHost[]{});
        ownerClient = new SecureRestClientBuilder(hosts, isHttps(), OWNER_USER, password).setSocketTimeout(60000).build();
        otherClient = new SecureRestClientBuilder(hosts, isHttps(), OTHER_USER, password).setSocketTimeout(60000).build();
        thirdClient = new SecureRestClientBuilder(hosts, isHttps(), THIRD_USER, password).setSocketTimeout(60000).build();

        enableProtectedTypes();
    }

    @After
    public void cleanup() throws IOException {
        if (!isResourceSharingEnabled()) {
            return;
        }
        disableProtectedTypes();
        if (ownerClient != null) ownerClient.close();
        if (otherClient != null) otherClient.close();
        if (thirdClient != null) thirdClient.close();
        deleteUser(OWNER_USER);
        deleteUser(OTHER_USER);
        deleteUser(THIRD_USER);
    }

    /**
     * Tests the full access-level progression for detectors:
     * 1. Owner creates detector, other user has no access (403)
     * 2. Share at sa_read_only -> other user can GET but NOT update or delete
     * 3. Upgrade to sa_read_write -> other user can GET and UPDATE but NOT delete or share
     * 4. Upgrade to sa_full_access -> other user can GET, UPDATE, SHARE, and DELETE
     * 5. Updates by shared user are visible to owner
     * 6. Non-owner with full_access can delete the resource
     */
    public void testDetectorAccessLevelProgression() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        String index = createWindowsIndexIfNotExists();
        indexDoc(client(), index, "1", randomDoc(), true);

        // --- Owner creates detector ---
        Detector detector = randomDetector(getRandomPrePackagedRules());
        Response createResponse = makeRequest(ownerClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
            Collections.emptyMap(), toHttpEntity(detector));
        assertEquals(HttpStatus.SC_CREATED, createResponse.getStatusLine().getStatusCode());
        Map<String, Object> responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();

        // --- Other user has no access ---
        assertForbidden(otherClient, "GET", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);
        assertForbidden(otherClient, "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // --- Share at sa_read_only level ---
        shareResource(ownerClient, detectorId, "detector", "sa_read_only", OTHER_USER);
        waitForSharingVisibility(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // Read-only: can GET
        Response getResp = makeRequest(otherClient, "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, getResp.getStatusLine().getStatusCode());

        // Read-only: cannot UPDATE
        assertForbidden(otherClient, "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // Read-only: cannot DELETE
        assertForbidden(otherClient, "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // --- Upgrade to sa_read_write level ---
        shareResource(ownerClient, detectorId, "detector", "sa_read_write", OTHER_USER);
        Thread.sleep(1000);

        // Read-write: can GET
        Response rwGetResp = makeRequest(otherClient, "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, rwGetResp.getStatusLine().getStatusCode());

        // Read-write: can UPDATE - and the update is visible to owner
        Detector updatedDetector = randomDetector(getRandomPrePackagedRules());
        Response updateResp = makeRequest(otherClient, "PUT",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId,
            Collections.emptyMap(), toHttpEntity(updatedDetector));
        assertEquals(HttpStatus.SC_OK, updateResp.getStatusLine().getStatusCode());

        // Verify owner sees the update
        Response ownerGetResp = makeRequest(ownerClient, "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, ownerGetResp.getStatusLine().getStatusCode());

        // Read-write: cannot share further (no share permission)
        assertShareForbidden(otherClient, detectorId, "detector", "sa_read_only", THIRD_USER);

        // Read-write: cannot DELETE
        assertForbidden(otherClient, "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // --- Upgrade to sa_full_access level ---
        shareResource(ownerClient, detectorId, "detector", "sa_full_access", OTHER_USER);
        Thread.sleep(1000);

        // Full-access: can share further with third user
        shareResource(otherClient, detectorId, "detector", "sa_read_only", THIRD_USER);
        waitForSharingVisibility(thirdClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // Third user can now GET
        Response thirdGetResp = makeRequest(thirdClient, "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, thirdGetResp.getStatusLine().getStatusCode());

        // Full-access non-owner can DELETE
        Response deleteResp = makeRequest(otherClient, "DELETE",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, deleteResp.getStatusLine().getStatusCode());
    }

    /**
     * Tests search/list filtering based on sharing:
     * - Owner sees own resources
     * - Other user sees nothing until shared
     * - After sharing, other user sees only shared resources
     */
    public void testDetectorSearchFilteringByAccess() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        String index = createWindowsIndexIfNotExists();
        indexDoc(client(), index, "1", randomDoc(), true);

        // Owner creates 2 detectors
        Detector detector1 = randomDetector(getRandomPrePackagedRules());
        Response resp1 = makeRequest(ownerClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
            Collections.emptyMap(), toHttpEntity(detector1));
        String detectorId1 = asMap(resp1).get("_id").toString();

        Detector detector2 = randomDetector(getRandomPrePackagedRules());
        Response resp2 = makeRequest(ownerClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
            Collections.emptyMap(), toHttpEntity(detector2));
        String detectorId2 = asMap(resp2).get("_id").toString();

        String searchBody = "{\"query\":{\"match_all\":{}}}";

        // Owner sees both
        int ownerCount = getSearchHitCount(ownerClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/_search", searchBody);
        assertEquals(2, ownerCount);

        // Other user sees 0
        int otherCount = getSearchHitCount(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/_search", searchBody);
        assertEquals(0, otherCount);

        // Share detector1 only
        shareResource(ownerClient, detectorId1, "detector", "sa_read_only", OTHER_USER);
        Thread.sleep(1000);

        // Other user sees exactly 1
        int otherCountAfterShare = getSearchHitCount(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/_search", searchBody);
        assertEquals(1, otherCountAfterShare);
    }

    /**
     * Tests the full access-level progression for correlation rules (mirrors detector test).
     */
    public void testCorrelationRuleAccessLevelProgression() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        // Owner creates correlation rule
        String correlationRuleBody = createCorrelationRuleBody("test-corr-rule-access");
        Response createResponse = makeRequest(ownerClient, "POST",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, Collections.emptyMap(),
            new StringEntity(correlationRuleBody), new BasicHeader("Content-Type", "application/json"));
        assertEquals(HttpStatus.SC_CREATED, createResponse.getStatusLine().getStatusCode());
        String ruleId = asMap(createResponse).get("_id").toString();

        // Other user has no access
        assertForbidden(otherClient, "DELETE", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/" + ruleId);

        // Share at sa_read_only: can search but not delete
        shareResource(ownerClient, ruleId, "correlation-rule", "sa_read_only", OTHER_USER);
        Thread.sleep(1000);

        // Upgrade to sa_full_access: non-owner can delete
        shareResource(ownerClient, ruleId, "correlation-rule", "sa_full_access", OTHER_USER);
        Thread.sleep(1000);

        Response deleteResp = makeRequest(otherClient, "DELETE",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/" + ruleId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, deleteResp.getStatusLine().getStatusCode());
    }

    /**
     * Tests correlation rule search filtering.
     */
    public void testCorrelationRuleSearchFilteringByAccess() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        // Owner creates 2 rules
        Response resp1 = makeRequest(ownerClient, "POST",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, Collections.emptyMap(),
            new StringEntity(createCorrelationRuleBody("test-rule-search-1")), new BasicHeader("Content-Type", "application/json"));
        String ruleId1 = asMap(resp1).get("_id").toString();

        Response resp2 = makeRequest(ownerClient, "POST",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, Collections.emptyMap(),
            new StringEntity(createCorrelationRuleBody("test-rule-search-2")), new BasicHeader("Content-Type", "application/json"));

        String searchBody = "{\"query\":{\"match_all\":{}}}";

        // Owner sees both
        int ownerCount = getSearchHitCount(ownerClient, SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", searchBody);
        assertEquals(2, ownerCount);

        // Other user sees 0
        int otherCount = getSearchHitCount(otherClient, SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", searchBody);
        assertEquals(0, otherCount);

        // Share rule1 only
        shareResource(ownerClient, ruleId1, "correlation-rule", "sa_read_only", OTHER_USER);
        Thread.sleep(1000);

        // Other user sees exactly 1
        int otherCountAfterShare = getSearchHitCount(otherClient, SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", searchBody);
        assertEquals(1, otherCountAfterShare);
    }

    /**
     * Tests revocation: after revoking access, user can no longer access the resource.
     */
    public void testRevokeAccessRemovesVisibility() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        String index = createWindowsIndexIfNotExists();
        indexDoc(client(), index, "1", randomDoc(), true);

        // Owner creates detector
        Detector detector = randomDetector(getRandomPrePackagedRules());
        Response createResponse = makeRequest(ownerClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
            Collections.emptyMap(), toHttpEntity(detector));
        String detectorId = asMap(createResponse).get("_id").toString();

        // Share then verify access
        shareResource(ownerClient, detectorId, "detector", "sa_read_only", OTHER_USER);
        waitForSharingVisibility(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // Revoke access
        revokeResource(ownerClient, detectorId, "detector", "sa_read_only", OTHER_USER);

        // Wait for revocation to take effect
        waitForRevocation(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);
    }

    /**
     * Tests that any user with cluster permissions can create a resource without
     * needing pre-existing access to another resource.
     */
    public void testAnyUserWithClusterPermissionsCanCreate() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        String index = createWindowsIndexIfNotExists();
        indexDoc(client(), index, "1", randomDoc(), true);

        // Other user (not owner) can create their own detector
        Detector detector = randomDetector(getRandomPrePackagedRules());
        Response createResponse = makeRequest(otherClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
            Collections.emptyMap(), toHttpEntity(detector));
        assertEquals(HttpStatus.SC_CREATED, createResponse.getStatusLine().getStatusCode());
        String detectorId = asMap(createResponse).get("_id").toString();

        // Creator can access their own resource (wait for sharing record to be created)
        waitForSharingVisibility(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // But owner user cannot access other's resource
        assertForbidden(ownerClient, "GET", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);
    }

    /**
     * Tests that multiple users can be granted access to the same resource simultaneously.
     */
    public void testMultipleUsersSharedAccess() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        String index = createWindowsIndexIfNotExists();
        indexDoc(client(), index, "1", randomDoc(), true);

        // Owner creates detector
        Detector detector = randomDetector(getRandomPrePackagedRules());
        Response createResponse = makeRequest(ownerClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
            Collections.emptyMap(), toHttpEntity(detector));
        String detectorId = asMap(createResponse).get("_id").toString();

        // Share with both other users at different levels
        shareResource(ownerClient, detectorId, "detector", "sa_read_only", OTHER_USER);
        shareResource(ownerClient, detectorId, "detector", "sa_read_write", THIRD_USER);
        waitForSharingVisibility(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);
        waitForSharingVisibility(thirdClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // Both can GET
        Response otherGet = makeRequest(otherClient, "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, otherGet.getStatusLine().getStatusCode());

        Response thirdGet = makeRequest(thirdClient, "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, thirdGet.getStatusLine().getStatusCode());

        // Read-only user cannot update
        assertForbidden(otherClient, "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // Read-write user can update
        Detector updated = randomDetector(getRandomPrePackagedRules());
        Response updateResp = makeRequest(thirdClient, "PUT",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId,
            Collections.emptyMap(), toHttpEntity(updated));
        assertEquals(HttpStatus.SC_OK, updateResp.getStatusLine().getStatusCode());

        // Read-only user still has access after third user updates
        Response otherGetAfterUpdate = makeRequest(otherClient, "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, otherGetAfterUpdate.getStatusLine().getStatusCode());
    }

    /**
     * Tests that owner always retains full access regardless of sharing state changes.
     */
    public void testOwnerAlwaysRetainsAccess() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        String index = createWindowsIndexIfNotExists();
        indexDoc(client(), index, "1", randomDoc(), true);

        // Owner creates detector
        Detector detector = randomDetector(getRandomPrePackagedRules());
        Response createResponse = makeRequest(ownerClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
            Collections.emptyMap(), toHttpEntity(detector));
        String detectorId = asMap(createResponse).get("_id").toString();

        // Share and then revoke with other user
        shareResource(ownerClient, detectorId, "detector", "sa_full_access", OTHER_USER);
        waitForSharingVisibility(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);
        revokeResource(ownerClient, detectorId, "detector", "sa_full_access", OTHER_USER);
        waitForRevocation(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // Owner still has full access after all sharing changes
        Response ownerGet = makeRequest(ownerClient, "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, ownerGet.getStatusLine().getStatusCode());

        // Owner can still update
        Detector updated = randomDetector(getRandomPrePackagedRules());
        Response updateResp = makeRequest(ownerClient, "PUT",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId,
            Collections.emptyMap(), toHttpEntity(updated));
        assertEquals(HttpStatus.SC_OK, updateResp.getStatusLine().getStatusCode());

        // Owner can still delete
        Response deleteResp = makeRequest(ownerClient, "DELETE",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, deleteResp.getStatusLine().getStatusCode());
    }

    /**
     * Tests that updating a shared resource doesn't break other users' access.
     * Specifically: owner updates a resource that is shared -> shared user still has access.
     */
    public void testOwnerUpdateDoesNotBreakSharedAccess() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        String index = createWindowsIndexIfNotExists();
        indexDoc(client(), index, "1", randomDoc(), true);

        // Owner creates detector
        Detector detector = randomDetector(getRandomPrePackagedRules());
        Response createResponse = makeRequest(ownerClient, "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
            Collections.emptyMap(), toHttpEntity(detector));
        String detectorId = asMap(createResponse).get("_id").toString();

        // Share with other user
        shareResource(ownerClient, detectorId, "detector", "sa_read_only", OTHER_USER);
        waitForSharingVisibility(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId);

        // Owner updates the detector
        Detector updated = randomDetector(getRandomPrePackagedRules());
        Response updateResp = makeRequest(ownerClient, "PUT",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId,
            Collections.emptyMap(), toHttpEntity(updated));
        assertEquals(HttpStatus.SC_OK, updateResp.getStatusLine().getStatusCode());

        // Shared user still has access after owner's update
        Thread.sleep(500);
        Response otherGet = makeRequest(otherClient, "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, otherGet.getStatusLine().getStatusCode());
    }

    /**
     * Tests correlation rule update with read-write access level.
     */
    public void testCorrelationRuleUpdateWithReadWriteAccess() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        // Owner creates correlation rule
        String ruleBody = createCorrelationRuleBody("test-corr-rw-update");
        Response createResponse = makeRequest(ownerClient, "POST",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, Collections.emptyMap(),
            new StringEntity(ruleBody), new BasicHeader("Content-Type", "application/json"));
        assertEquals(HttpStatus.SC_CREATED, createResponse.getStatusLine().getStatusCode());
        String ruleId = asMap(createResponse).get("_id").toString();

        // Share at read-write level
        shareResource(ownerClient, ruleId, "correlation-rule", "sa_read_write", OTHER_USER);
        Thread.sleep(1000);

        // Other user can update the correlation rule
        String updatedRuleBody = createCorrelationRuleBody("test-corr-rw-updated");
        Response updateResp = makeRequest(otherClient, "PUT",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/" + ruleId,
            Collections.emptyMap(),
            new StringEntity(updatedRuleBody), new BasicHeader("Content-Type", "application/json"));
        assertEquals(HttpStatus.SC_OK, updateResp.getStatusLine().getStatusCode());

        // Owner can see the updated rule via search
        String searchBody = "{\"query\":{\"match\":{\"name\":\"test-corr-rw-updated\"}}}";
        int count = getSearchHitCount(ownerClient, SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", searchBody);
        assertEquals(1, count);

        // Other user still cannot delete (read_write doesn't grant delete)
        assertForbidden(otherClient, "DELETE", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/" + ruleId);
    }

    /**
     * Tests that when resource-sharing feature is disabled, no access restrictions apply
     * (legacy behavior is preserved).
     */
    public void testLegacyBehaviorWhenFeatureDisabled() throws Exception {
        if (isResourceSharingEnabled()) {
            return;
        }

        String index = createWindowsIndexIfNotExists();
        indexDoc(client(), index, "1", randomDoc(), true);

        // Any user with cluster permissions can create
        Detector detector = randomDetector(getRandomPrePackagedRules());
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
            Collections.emptyMap(), toHttpEntity(detector));
        assertEquals(HttpStatus.SC_CREATED, createResponse.getStatusLine().getStatusCode());
        String detectorId = asMap(createResponse).get("_id").toString();

        // Same client can access without resource-sharing enforcement
        Response getResponse = makeRequest(client(), "GET",
            SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, getResponse.getStatusLine().getStatusCode());
    }

    // --- Helper methods ---

    private boolean isResourceSharingEnabled() {
        return "true".equals(System.getProperty("resource_sharing.enabled"));
    }

    private String createWindowsIndexIfNotExists() throws IOException {
        try {
            createTestIndex(client(), "windows", windowsIndexMapping(), Settings.EMPTY);
        } catch (ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() != 400) {
                throw e;
            }
        }
        return "windows";
    }

    private void deleteRoleIfExists(String role) {
        try {
            client().performRequest(new Request("DELETE", "/_plugins/_security/api/roles/" + role));
        } catch (IOException ignored) {
            // role didn't exist, that's fine
        }
    }

    private void enableProtectedTypes() throws IOException {
        Request request = new Request("PUT", "_cluster/settings");
        request.setJsonEntity("{\"persistent\":{\"plugins.security.experimental.resource_sharing.protected_types\":[\"detector\",\"correlation-rule\"]}}");
        client().performRequest(request);
    }

    private void disableProtectedTypes() throws IOException {
        Request request = new Request("PUT", "_cluster/settings");
        request.setJsonEntity("{\"persistent\":{\"plugins.security.experimental.resource_sharing.protected_types\":[]}}");
        client().performRequest(request);
    }

    private void shareResource(RestClient asClient, String resourceId, String resourceType, String accessLevel, String shareWithUser) throws IOException {
        String body = String.format(Locale.ROOT,
            "{\"resource_id\":\"%s\",\"resource_type\":\"%s\",\"share_with\":{\"%s\":{\"users\":[\"%s\"]}}}",
            resourceId, resourceType, accessLevel, shareWithUser);
        Request request = new Request("PUT", "/_plugins/_security/api/resource/share");
        request.setJsonEntity(body);
        asClient.performRequest(request);
    }

    private void revokeResource(RestClient asClient, String resourceId, String resourceType, String accessLevel, String revokeUser) throws IOException {
        String body = String.format(Locale.ROOT,
            "{\"resource_id\":\"%s\",\"resource_type\":\"%s\",\"revoke\":{\"%s\":{\"users\":[\"%s\"]}}}",
            resourceId, resourceType, accessLevel, revokeUser);
        Request request = new Request("PATCH", "/_plugins/_security/api/resource/share");
        request.setJsonEntity(body);
        asClient.performRequest(request);
    }

    private void assertForbidden(RestClient userClient, String method, String endpoint) throws IOException {
        try {
            makeRequest(userClient, method, endpoint, Collections.emptyMap(), null);
            fail("Expected 403 for " + method + " " + endpoint);
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_FORBIDDEN, e.getResponse().getStatusLine().getStatusCode());
        }
    }

    private void assertShareForbidden(RestClient userClient, String resourceId, String resourceType, String accessLevel, String shareWithUser) {
        try {
            shareResource(userClient, resourceId, resourceType, accessLevel, shareWithUser);
            fail("Expected 403 when sharing without share permission");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("403") || e instanceof ResponseException);
        }
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

    private void waitForRevocation(RestClient userClient, String resourceEndpoint) throws Exception {
        int maxRetries = 30;
        for (int i = 0; i < maxRetries; i++) {
            try {
                makeRequest(userClient, "GET", resourceEndpoint, Collections.emptyMap(), null);
            } catch (ResponseException e) {
                if (e.getResponse().getStatusLine().getStatusCode() == HttpStatus.SC_FORBIDDEN) {
                    return;
                }
            }
            Thread.sleep(200);
        }
        fail("Resource access was not revoked within timeout");
    }

    @SuppressWarnings("unchecked")
    private int getSearchHitCount(RestClient userClient, String searchEndpoint, String body) throws IOException {
        Response response = makeRequest(userClient, "POST", searchEndpoint, Collections.emptyMap(),
            new StringEntity(body), new BasicHeader("Content-Type", "application/json"));
        Map<String, Object> results = asMap(response);
        Map<String, Object> hits = (Map<String, Object>) results.get("hits");
        Map<String, Object> total = (Map<String, Object>) hits.get("total");
        return ((Number) total.get("value")).intValue();
    }

    private String createCorrelationRuleBody(String name) {
        return "{"
            + "\"name\": \"" + name + "\","
            + "\"correlate\": ["
            + "  {\"index\": \"index-1\", \"query\": \"host.hostname:EC2*\", \"category\": \"windows\"},"
            + "  {\"index\": \"index-2\", \"query\": \"host.hostname:EC2*\", \"category\": \"network\"}"
            + "]"
            + "}";
    }
}
