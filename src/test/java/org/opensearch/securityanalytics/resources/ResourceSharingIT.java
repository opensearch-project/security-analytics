/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resources;

import org.apache.hc.core5.http.HttpEntity;
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
import org.opensearch.securityanalytics.model.CorrelationRule;
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

    // Fixed password for the bootstrap-provisioned test users. Must match the bcrypt hash in
    // src/test/resources/resource-sharing-security-config/internal_users.yml.
    private static final String BOOTSTRAP_USER_PASSWORD = "ResourceSharingItPass123!";

    private RestClient ownerClient;
    private RestClient otherClient;
    private RestClient thirdClient;

    // Resource-sharing ownership/DLS records are populated asynchronously by the security plugin
    // (ResourceIndexListener writes the ownership record fire-and-forget after the resource is indexed).
    // Under CI load on a single-node cluster this propagation can take tens of seconds, so poll
    // generously (240 x 500ms = 120s). A 500ms interval (rather than a tighter loop) is deliberate:
    // it keeps the polling from adding request load to an already-saturated cluster, which would slow
    // the very propagation being waited on.
    private static final int MAX_POLL_RETRIES = 240;
    private static final long POLL_INTERVAL_MILLIS = 500L;

    @Before
    public void setup() throws Exception {
        if (!isResourceSharingEnabled()) {
            return;
        }

        // The test users, sa_extra_role, and their role mappings are provisioned as the security plugin's
        // bootstrap configuration (see src/test/resources/resource-sharing-security-config and the
        // resource_sharing cluster block in build.gradle), so they are fully effective at cluster startup.
        // This deliberately avoids creating users/roles via the REST API here: runtime creation triggers an
        // async security-config reload whose lag under CI load made this suite flaky. The bootstrap users
        // authenticate with a fixed password (matching the bcrypt hash in internal_users.yml).
        HttpHost[] hosts = getClusterHosts().toArray(new HttpHost[]{});
        ownerClient = new SecureRestClientBuilder(hosts, isHttps(), OWNER_USER, BOOTSTRAP_USER_PASSWORD).setSocketTimeout(60000).build();
        otherClient = new SecureRestClientBuilder(hosts, isHttps(), OTHER_USER, BOOTSTRAP_USER_PASSWORD).setSocketTimeout(60000).build();
        thirdClient = new SecureRestClientBuilder(hosts, isHttps(), THIRD_USER, BOOTSTRAP_USER_PASSWORD).setSocketTimeout(60000).build();
    }

    @After
    public void cleanup() throws IOException {
        if (!isResourceSharingEnabled()) {
            return;
        }
        // The users/roles are bootstrap-provisioned config (not created at runtime), so there is nothing
        // to delete here - only close the per-test REST clients.
        if (ownerClient != null) ownerClient.close();
        if (otherClient != null) otherClient.close();
        if (thirdClient != null) thirdClient.close();
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

        // Wait until the owner's ownership record is durable before asserting on other users
        waitForOwnershipRecord(Detector.DETECTORS_INDEX, detectorId);

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

        // Read-only: cannot UPDATE (send a valid body so the request reaches authorization)
        assertForbidden(otherClient, "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId,
            toHttpEntity(randomDetector(getRandomPrePackagedRules())));

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

        // Read-write: cannot share further (share requires full_access)
        assertShareForbidden(otherClient, detectorId, "detector", "sa_read_only", THIRD_USER);

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

        // Ensure the DLS principals field is populated on both detectors before searching - that field is
        // what the owner's DLS-filtered search matches on, and it is written after the ownership record.
        waitForDlsPrincipals(Detector.DETECTORS_INDEX, detectorId1);
        waitForDlsPrincipals(Detector.DETECTORS_INDEX, detectorId2);

        String searchBody = "{\"query\":{\"match_all\":{}}}";

        // Owner sees both (DLS principal population is eventually consistent)
        assertSearchHitCountEventually(ownerClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/_search", searchBody, 2);

        // Other user sees 0
        assertSearchHitCountEventually(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/_search", searchBody, 0);

        // Share detector1 only
        shareResource(ownerClient, detectorId1, "detector", "sa_read_only", OTHER_USER);

        // Other user sees exactly 1
        assertSearchHitCountEventually(otherClient, SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/_search", searchBody, 1);
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
        String ruleId2 = asMap(resp2).get("_id").toString();

        // Ensure the DLS principals field is populated on both rules before searching - that field is what
        // the owner's DLS-filtered search matches on, and it is written after the ownership record.
        waitForDlsPrincipals(CorrelationRule.CORRELATION_RULE_INDEX, ruleId1);
        waitForDlsPrincipals(CorrelationRule.CORRELATION_RULE_INDEX, ruleId2);

        String searchBody = "{\"query\":{\"match_all\":{}}}";

        // Owner sees both (DLS principal population is eventually consistent)
        assertSearchHitCountEventually(ownerClient, SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", searchBody, 2);

        // Other user sees 0
        assertSearchHitCountEventually(otherClient, SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", searchBody, 0);

        // Share rule1 only
        shareResource(ownerClient, ruleId1, "correlation-rule", "sa_read_only", OTHER_USER);

        // Other user sees exactly 1
        assertSearchHitCountEventually(otherClient, SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", searchBody, 1);
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

        // Wait for the owner's ownership record to be durable before
        // sharing, so the share API recognizes the caller as the owner rather than returning 403.
        waitForOwnershipRecord(Detector.DETECTORS_INDEX, detectorId);

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

        // Wait for the ownership record to be durable, then verify the creator can access their resource.
        waitForOwnershipRecord(Detector.DETECTORS_INDEX, detectorId);
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

        // Wait for the owner's ownership record to be durable before sharing.
        waitForOwnershipRecord(Detector.DETECTORS_INDEX, detectorId);

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

        // Read-only user cannot update (send a valid body so the request reaches authorization)
        assertForbidden(otherClient, "PUT", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId,
            toHttpEntity(randomDetector(getRandomPrePackagedRules())));

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

        // Wait for the owner's ownership record to be durable before sharing.
        waitForOwnershipRecord(Detector.DETECTORS_INDEX, detectorId);

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

        // Wait for the owner's ownership record to be durable before sharing.
        waitForOwnershipRecord(Detector.DETECTORS_INDEX, detectorId);

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

        // Other user can update the correlation rule
        String updatedRuleBody = createCorrelationRuleBody("test-corr-rw-updated");
        Response updateResp = makeRequest(otherClient, "PUT",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/" + ruleId,
            Collections.emptyMap(),
            new StringEntity(updatedRuleBody), new BasicHeader("Content-Type", "application/json"));
        assertEquals(HttpStatus.SC_OK, updateResp.getStatusLine().getStatusCode());

        // Owner can see the updated rule via search
        String searchBody = "{\"query\":{\"match\":{\"name\":\"test-corr-rw-updated\"}}}";
        assertSearchHitCountEventually(ownerClient, SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", searchBody, 1);

        // read_write grants delete (per resource-access-levels.yml)
        Response deleteResp = makeRequest(otherClient, "DELETE",
            SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/" + ruleId, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, deleteResp.getStatusLine().getStatusCode());
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

    private void shareResource(RestClient asClient, String resourceId, String resourceType, String accessLevel, String shareWithUser) throws Exception {
        String body = String.format(Locale.ROOT,
            "{\"resource_id\":\"%s\",\"resource_type\":\"%s\",\"share_with\":{\"%s\":{\"users\":[\"%s\"]}}}",
            resourceId, resourceType, accessLevel, shareWithUser);
        // The ownership record is created asynchronously by the security plugin's
        // ResourceIndexListener after the resource is written. Until it is durable, the share API
        // sees the caller as a non-owner and returns 403. Poll (treating 403 as eventual
        // consistency) until the owner can share, mirroring the anomaly-detection / reporting ITs.
        ResponseException lastFailure = null;
        for (int i = 0; i < MAX_POLL_RETRIES; i++) {
            Request request = new Request("PUT", "/_plugins/_security/api/resource/share");
            request.setJsonEntity(body);
            try {
                asClient.performRequest(request);
                return;
            } catch (ResponseException e) {
                if (e.getResponse().getStatusLine().getStatusCode() != HttpStatus.SC_FORBIDDEN) {
                    throw e;
                }
                lastFailure = e;
            }
            Thread.sleep(POLL_INTERVAL_MILLIS);
        }
        throw lastFailure;
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
        assertForbidden(userClient, method, endpoint, null);
    }

    /**
     * Asserts the request is rejected with 403. A body must be supplied for update (PUT/POST)
     * operations so the request is well-formed and actually reaches the authorization layer;
     * otherwise the REST handler fails body parsing with 400 before authorization runs.
     */
    private void assertForbidden(RestClient userClient, String method, String endpoint, HttpEntity body) throws IOException {
        try {
            makeRequest(userClient, method, endpoint, Collections.emptyMap(), body);
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
        for (int i = 0; i < MAX_POLL_RETRIES; i++) {
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
            Thread.sleep(POLL_INTERVAL_MILLIS);
        }
        fail("Resource did not become visible within timeout");
    }

    private void waitForRevocation(RestClient userClient, String resourceEndpoint) throws Exception {
        for (int i = 0; i < MAX_POLL_RETRIES; i++) {
            try {
                makeRequest(userClient, "GET", resourceEndpoint, Collections.emptyMap(), null);
            } catch (ResponseException e) {
                if (e.getResponse().getStatusLine().getStatusCode() == HttpStatus.SC_FORBIDDEN) {
                    return;
                }
            }
            Thread.sleep(POLL_INTERVAL_MILLIS);
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

    /**
     * Polls the security plugin's resource-sharing index directly (as super-admin, bypassing DLS) until the
     * ownership record for the resource is durable. Its document _id is the resource id, so a GET by _id is
     * an exact lookup. A 404 (not yet written) or 503 (sharing-index shard still RECOVERING) are transient.
     * This is the precondition for the owner being recognized by the share API.
     */
    private void waitForOwnershipRecord(String resourceIndex, String resourceId) throws Exception {
        String sharingIndex = resourceIndex + "-sharing";
        for (int i = 0; i < MAX_POLL_RETRIES; i++) {
            try {
                adminClient().performRequest(new Request("GET", "/" + sharingIndex + "/_doc/" + resourceId));
                return;
            } catch (ResponseException e) {
                int status = e.getResponse().getStatusLine().getStatusCode();
                if (status != HttpStatus.SC_NOT_FOUND && status != HttpStatus.SC_SERVICE_UNAVAILABLE) {
                    throw e;
                }
            }
            Thread.sleep(POLL_INTERVAL_MILLIS);
        }
        fail("Ownership record for resource " + resourceId + " did not become durable within timeout");
    }

    /**
     * Polls (as super-admin, bypassing DLS) until the resource document's all_shared_principals field is
     * populated. The security plugin writes this field to the resource doc via updateResourceVisibility,
     * which runs AFTER the ownership record is created - and it is the field the resource-sharing DLS
     * filters on. Gating on it is therefore the exact precondition for the owner's DLS-filtered search to
     * return the resource, and confirms the full ownership pipeline (record + visibility) has completed.
     */
    @SuppressWarnings("unchecked")
    private void waitForDlsPrincipals(String resourceIndex, String resourceId) throws Exception {
        for (int i = 0; i < MAX_POLL_RETRIES; i++) {
            try {
                Response response = adminClient().performRequest(new Request("GET", "/" + resourceIndex + "/_doc/" + resourceId));
                Map<String, Object> doc = asMap(response);
                Map<String, Object> source = (Map<String, Object>) doc.get("_source");
                Object principals = source == null ? null : source.get("all_shared_principals");
                if (principals instanceof List && !((List<?>) principals).isEmpty()) {
                    return;
                }
            } catch (ResponseException e) {
                int status = e.getResponse().getStatusLine().getStatusCode();
                if (status != HttpStatus.SC_NOT_FOUND && status != HttpStatus.SC_SERVICE_UNAVAILABLE) {
                    throw e;
                }
            }
            Thread.sleep(POLL_INTERVAL_MILLIS);
        }
        fail("all_shared_principals for resource " + resourceId + " was not populated within timeout");
    }

    /**
     * Polls the search endpoint until it returns the expected hit count. The security plugin
     * populates the all_shared_principals field (used by resource-sharing DLS) asynchronously
     * after a resource is created or shared, so search visibility is eventually consistent.
     */
    private void assertSearchHitCountEventually(RestClient userClient, String searchEndpoint, String body, int expected) throws Exception {
        int actual = -1;
        for (int i = 0; i < MAX_POLL_RETRIES; i++) {
            actual = getSearchHitCount(userClient, searchEndpoint, body);
            if (actual == expected) {
                return;
            }
            Thread.sleep(POLL_INTERVAL_MILLIS);
        }
        assertEquals(expected, actual);
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
