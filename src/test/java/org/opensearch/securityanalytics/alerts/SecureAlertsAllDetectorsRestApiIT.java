/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerts;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.After;
import org.junit.Before;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.commons.rest.SecureRestClientBuilder;

/**
 * Alerts of all detectors (no detector_id / detectorType) only include the alerts of detectors the caller can see.
 */
public class SecureAlertsAllDetectorsRestApiIT extends AlertsAllDetectorsTestCase {

    private static final String FULL_ACCESS_ROLE = "security_analytics_full_access";
    private static final String READ_ACCESS_ROLE = "security_analytics_read_access";
    private static final String INDEX_ROLE = "alerts_all_detectors_index_role";
    private static final String NO_ALERTS_ROLE = "alerts_all_detectors_no_get_alerts_role";
    /** Read access to alerts with cursor paging, which needs the get_page permission besides the get permission */
    private static final String CURSOR_READ_ROLE = "alerts_all_detectors_cursor_read_role";

    private static final String USER_A = "alerts_user_a";
    private static final String USER_B = "alerts_user_b";
    private static final String USER_READ = "alerts_user_read";
    private static final String USER_NO_BACKEND_ROLES = "alerts_user_no_backend_roles";
    private static final String USER_NO_ALERTS_PERMISSION = "alerts_user_no_alerts_permission";
    private static final String USER_CURSOR_READ = "alerts_user_cursor_read";

    private static final String BACKEND_ROLE_A = "alerts_backend_role_a";
    private static final String BACKEND_ROLE_B = "alerts_backend_role_b";
    private static final String BACKEND_ROLE_READ = "alerts_backend_role_read";

    private RestClient userAClient;
    private RestClient userBClient;
    private RestClient readClient;
    private RestClient noBackendRolesClient;
    private RestClient noAlertsPermissionClient;
    private RestClient cursorReadClient;

    @Before
    public void createUsers() throws Exception {
        createUser(USER_A, new String[] { BACKEND_ROLE_A });
        createUser(USER_B, new String[] { BACKEND_ROLE_B });
        createUser(USER_READ, new String[] { BACKEND_ROLE_READ });
        createUser(USER_NO_BACKEND_ROLES, new String[0]);
        createUser(USER_NO_ALERTS_PERMISSION, new String[] { BACKEND_ROLE_A });
        createUser(USER_CURSOR_READ, new String[] { BACKEND_ROLE_READ });
        createIndexRole(CURSOR_READ_ROLE, List.of(
                "cluster:admin/opensearch/securityanalytics/alerts/get",
                "cluster:admin/opensearch/securityanalytics/alerts/get_page",
                "cluster:admin/opensearch/securityanalytics/detector/get",
                "cluster:admin/opensearch/securityanalytics/detector/search"), indexPermissions, List.of(WINDOWS_INDEX));
        createIndexRole(INDEX_ROLE, List.of(), indexPermissions, List.of(WINDOWS_INDEX, NETWORK_INDEX));
        createCustomRole(NO_ALERTS_ROLE, "cluster:admin/opensearch/securityanalytics/detector/search");
        mapUsersToRole(FULL_ACCESS_ROLE, USER_A, USER_B);
        mapUsersToRole(INDEX_ROLE, USER_A, USER_B);
        mapUsersToRole(READ_ACCESS_ROLE, USER_READ, USER_NO_BACKEND_ROLES);
        mapUsersToRole(NO_ALERTS_ROLE, USER_NO_ALERTS_PERMISSION);
        mapUsersToRole(CURSOR_READ_ROLE, USER_CURSOR_READ);

        HttpHost[] hosts = getClusterHosts().toArray(new HttpHost[] {});
        userAClient = new SecureRestClientBuilder(hosts, isHttps(), USER_A, password).setSocketTimeout(60000).build();
        userBClient = new SecureRestClientBuilder(hosts, isHttps(), USER_B, password).setSocketTimeout(60000).build();
        readClient = new SecureRestClientBuilder(hosts, isHttps(), USER_READ, password).setSocketTimeout(60000).build();
        noBackendRolesClient = new SecureRestClientBuilder(hosts, isHttps(), USER_NO_BACKEND_ROLES, password).setSocketTimeout(60000).build();
        noAlertsPermissionClient = new SecureRestClientBuilder(hosts, isHttps(), USER_NO_ALERTS_PERMISSION, password).setSocketTimeout(60000).build();
        cursorReadClient = new SecureRestClientBuilder(hosts, isHttps(), USER_CURSOR_READ, password).setSocketTimeout(60000).build();

        // user / role mapping changes are applied asynchronously
        waitForRoles(userAClient, FULL_ACCESS_ROLE, INDEX_ROLE);
        waitForRoles(userBClient, FULL_ACCESS_ROLE, INDEX_ROLE);
        waitForRoles(readClient, READ_ACCESS_ROLE);
        waitForRoles(noBackendRolesClient, READ_ACCESS_ROLE);
        waitForRoles(noAlertsPermissionClient, NO_ALERTS_ROLE);
        waitForRoles(cursorReadClient, CURSOR_READ_ROLE);
    }

    @After
    public void deleteUsers() throws IOException {
        for (RestClient restClient : Arrays.asList(userAClient, userBClient, readClient, noBackendRolesClient, noAlertsPermissionClient,
                cursorReadClient)) {
            if (restClient != null) {
                restClient.close();
            }
        }
        enableOrDisableFilterBy("false");
        for (String user : List.of(USER_A, USER_B, USER_READ, USER_NO_BACKEND_ROLES, USER_NO_ALERTS_PERMISSION, USER_CURSOR_READ)) {
            deleteUser(user);
        }
        tryDeletingRole(INDEX_ROLE);
        tryDeletingRole(NO_ALERTS_ROLE);
        tryDeletingRole(CURSOR_READ_ROLE);
    }

    public void testGetAlertsWithoutDetector_filterByBackendRoles() throws Exception {
        // user A creates the windows detector, user B the network detector
        AlertsFixture fixture = createAlertsFixture(userAClient, userBClient);
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());
        String alertingMonitorName = "plainalertingmonitor";
        Set<String> alertingAlertIds = Set.copyOf(createAlertingMonitorWithAlert(alertingMonitorName, WINDOWS_INDEX));

        enableOrDisableFilterBy("true");

        // every user only gets the alerts of the detectors created by users sharing a backend role
        assertAlerts(fixture, getAlertsApi(userAClient, Map.of()), fixture.windowsAlertIds());
        assertAlerts(fixture, getAlertsApi(userBClient, Map.of()), fixture.networkAlertIds());
        assertAlerts(fixture, getAlertsApi(userAClient, params("sortString", "severity", "sortOrder", "desc", "size", "100")),
                fixture.windowsAlertIds());
        assertAlerts(fixture, getAlertsApi(userBClient, params("severityLevels", "1,2,3,4", "alertStates", "ACTIVE")),
                fixture.networkAlertIds());
        // the other user's alerts are not reachable through search strings either
        assertAlerts(fixture, getAlertsApi(userAClient, params("searchString", NETWORK_DETECTOR_NAME)), Set.of());
        assertAlerts(fixture, getAlertsApi(userBClient, params("searchString", WINDOWS_DETECTOR_NAME)), Set.of());

        // paging: the totals are the visible alerts, the pages cover them exactly once
        List<String> userAAll = alertIdsOf(getAlertsApi(userAClient, params("size", "100")));
        assertEquals(userAAll, fetchAllPages(userAClient, Map.of(), 3, 8));
        List<String> userBAll = alertIdsOf(getAlertsApi(userBClient, params("size", "100")));
        assertEquals(userBAll, fetchAllPages(userBClient, Map.of(), 4, 6));
        Map<String, Object> totalOnly = getAlertsApi(userAClient, params("size", "0"));
        assertEquals(8, totalOnly.get("total_alerts"));
        assertEquals(List.of(), totalOnly.get("alerts"));

        // the detector_id and detectorType modes keep their semantics
        assertAlerts(fixture, getAlertsApi(userAClient, params("detector_id", fixture.windowsDetectorId)), fixture.windowsAlertIds());
        assertAlerts(fixture, getAlertsApi(userAClient, params("detectorType", WINDOWS_LOG_TYPE)), fixture.windowsAlertIds());
        assertStatus(HttpStatus.SC_FORBIDDEN, userAClient, params("detector_id", fixture.networkDetectorId));
        assertStatus(HttpStatus.SC_NOT_FOUND, userAClient, params("detectorType", NETWORK_LOG_TYPE));

        // a user with read access whose backend role matches no detector creator: no alerts (not other users' alerts)
        Map<String, Object> readBody = getAlertsApi(readClient, Map.of());
        assertEquals(List.of(), readBody.get("alerts"));
        assertEquals(0, readBody.get("total_alerts"));
        assertAlerts(fixture, getAlertsApi(readClient, params("searchString", WINDOWS_DETECTOR_NAME)), Set.of());
        assertAlerts(fixture, getAlertsApi(readClient, params("searchString", alertingMonitorName)), Set.of());

        // a user without backend roles is rejected when filtering by backend roles
        assertStatus(HttpStatus.SC_FORBIDDEN, noBackendRolesClient, Map.of());
        // a user without the get alerts permission is rejected
        assertStatus(HttpStatus.SC_FORBIDDEN, noAlertsPermissionClient, Map.of());

        // Alerting plugin alerts are never returned to non admin users
        for (RestClient restClient : List.of(userAClient, userBClient, readClient)) {
            for (Map<String, String> request : List.of(Map.<String, String>of(), params("size", "100"),
                    params("searchString", alertingMonitorName), params("detectorType", restClient == userBClient ? NETWORK_LOG_TYPE : WINDOWS_LOG_TYPE))) {
                if (restClient == readClient && request.containsKey("detectorType")) {
                    continue;
                }
                List<String> ids = alertIdsOf(getAlertsApi(restClient, request));
                assertTrue(request + " returned " + ids, allIds.containsAll(ids));
                assertTrue(ids.stream().noneMatch(alertingAlertIds::contains));
            }
        }

        // without backend role filtering every user with alerts access sees the alerts of all detectors
        enableOrDisableFilterBy("false");
        assertAlerts(fixture, getAlertsApi(userAClient, Map.of()), allIds);
        assertAlerts(fixture, getAlertsApi(readClient, Map.of()), allIds);
        assertAlerts(fixture, getAlertsApi(noBackendRolesClient, Map.of()), allIds);
        assertAlerts(fixture, getAlertsApi(readClient, params("searchString", alertingMonitorName)), Set.of());
        assertStatus(HttpStatus.SC_FORBIDDEN, noAlertsPermissionClient, Map.of());
    }

    public void testGetAlertsWithoutDetector_noVisibleDetectors_returnsEmpty() throws Exception {
        // no detectors index at all
        enableOrDisableFilterBy("true");
        Map<String, Object> body = getAlertsApi(readClient, Map.of());
        assertEquals(List.of(), body.get("alerts"));
        assertEquals(0, body.get("total_alerts"));
        assertStatus(HttpStatus.SC_FORBIDDEN, noBackendRolesClient, Map.of());
        // invalid parameters are rejected for non admin users too
        assertStatus(HttpStatus.SC_BAD_REQUEST, readClient, params("sortString", "monitor_name"));
    }

    /**
     * Cursor paging (paging=cursor) only returns the alerts of the detectors visible to the caller, like offset paging:
     * per user with backend role filtering, for all detectors, a detector id and a detector type. Cursors only position
     * pages, so another user's cursor does not give access to that user's alerts.
     */
    public void testCursorPaging_filterByBackendRoles() throws Exception {
        AlertsFixture fixture = createAlertsFixture(userAClient, userBClient);
        Set<String> allIds = union(fixture.windowsAlertIds(), fixture.networkAlertIds());
        enableOrDisableFilterBy("true");

        assertEquals(fixture.windowsAlertIds(), walkCursorPages(userAClient, Map.of(), 3, 8));
        assertEquals(fixture.networkAlertIds(), walkCursorPages(userBClient, Map.of(), 4, 6));
        assertEquals(fixture.windowsAlertIds(), walkCursorPages(userAClient, params("sortString", "severity", "sortOrder", "desc"), 5, 8));
        assertEquals(Set.of(), walkCursorPages(userAClient, params("searchString", NETWORK_DETECTOR_NAME), 3, 0));
        // detector id and detector type: the same access checks as offset paging
        assertEquals(fixture.windowsAlertIds(), walkCursorPages(userAClient, params("detector_id", fixture.windowsDetectorId), 3, 8));
        assertEquals(fixture.windowsAlertIds(), walkCursorPages(userAClient, params("detectorType", WINDOWS_LOG_TYPE), 3, 8));
        assertStatus(HttpStatus.SC_FORBIDDEN, userAClient, params("detector_id", fixture.networkDetectorId));
        assertStatus(HttpStatus.SC_FORBIDDEN, userAClient, params("paging", "cursor", "detector_id", fixture.networkDetectorId));
        assertStatus(HttpStatus.SC_NOT_FOUND, userAClient, params("paging", "cursor", "detectorType", NETWORK_LOG_TYPE));

        // user B's cursor positions user A's page, which still only has user A's alerts
        Map<String, String> bySeverity = params("paging", "cursor", "sortString", "severity", "sortOrder", "asc", "size", "2");
        String userBCursor = (String) getAlertsApi(userBClient, bySeverity).get("next_cursor");
        assertNotNull(userBCursor);
        Map<String, String> withUserBCursor = new HashMap<>(bySeverity);
        withUserBCursor.put("searchAfter", userBCursor);
        for (String direction : List.of("next", "prev")) {
            withUserBCursor.put("direction", direction);
            Map<String, Object> page = getAlertsApi(userAClient, withUserBCursor);
            assertTrue(fixture.windowsAlertIds().containsAll(alertIdsOf(page)));
            assertEquals(8, page.get("total_alerts"));
        }

        // a user with cursor paging access whose backend role matches no detector creator: no alerts, no cursors
        Map<String, Object> empty = getAlertsApi(cursorReadClient, params("paging", "cursor"));
        assertEquals(List.of(), empty.get("alerts"));
        assertEquals(0, empty.get("total_alerts"));
        assertNull(empty.get("next_cursor"));
        assertNull(empty.get("prev_cursor"));
        assertTrue(empty.containsKey("next_cursor"));
        assertEquals(Set.of(), walkCursorPages(cursorReadClient, params("searchString", WINDOWS_DETECTOR_NAME), 3, 0));
        // the security_analytics_read_access role can page with cursors too: no alerts, like offset paging
        assertEquals(Set.of(), walkCursorPages(readClient, Map.of(), 3, 0));
        assertEquals(0, getAlertsApi(readClient, Map.of()).get("total_alerts"));
        // users without backend roles are rejected when filtering by backend roles, users without alerts access always
        assertStatus(HttpStatus.SC_FORBIDDEN, noBackendRolesClient, params("paging", "cursor"));
        assertStatus(HttpStatus.SC_FORBIDDEN, noAlertsPermissionClient, params("paging", "cursor"));
        // invalid cursor paging params are rejected for non admin users too
        assertStatus(HttpStatus.SC_BAD_REQUEST, cursorReadClient, params("paging", "cursor", "searchAfter", "tampered"));

        // without backend role filtering every user with cursor paging access sees the alerts of all detectors
        enableOrDisableFilterBy("false");
        assertEquals(allIds, walkCursorPages(cursorReadClient, Map.of(), 5, 14));
        assertEquals(allIds, walkCursorPages(userBClient, Map.of(), 14, 14));
        assertEquals(allIds, walkCursorPages(readClient, Map.of(), 5, 14));
    }

    /** Walks all cursor pages, checking the exact total of every page, and returns the alert ids without duplicates. */
    private Set<String> walkCursorPages(RestClient restClient, Map<String, String> params, int size, int expectedTotal) throws IOException {
        List<String> ids = new java.util.ArrayList<>();
        Map<String, String> pageParams = new HashMap<>(params);
        pageParams.put("paging", "cursor");
        pageParams.put("size", String.valueOf(size));
        for (int pages = 0; pages <= expectedTotal / size + 1; pages++) {
            Map<String, Object> page = getAlertsApi(restClient, pageParams);
            assertEquals(expectedTotal, page.get("total_alerts"));
            ids.addAll(alertIdsOf(page));
            String nextCursor = (String) page.get("next_cursor");
            if (nextCursor == null) {
                assertEquals("duplicates in " + ids, ids.size(), Set.copyOf(ids).size());
                assertEquals(expectedTotal, ids.size());
                return Set.copyOf(ids);
            }
            pageParams.put("searchAfter", nextCursor);
        }
        throw new AssertionError("too many pages: " + ids);
    }

    private void assertStatus(int expectedStatus, RestClient restClient, Map<String, String> params) {
        ResponseException e = expectThrows(ResponseException.class, () -> getAlertsApi(restClient, params));
        assertEquals(params.toString(), expectedStatus, e.getResponse().getStatusLine().getStatusCode());
    }

    private void mapUsersToRole(String role, String... users) throws IOException {
        Request request = new Request("PUT", "/_plugins/_security/api/rolesmapping/" + role);
        request.setJsonEntity("{\"backend_roles\":[],\"hosts\":[],\"users\":["
                + Arrays.stream(users).map(u -> "\"" + u + "\"").collect(Collectors.joining(",")) + "]}");
        client().performRequest(request);
    }

    @SuppressWarnings("unchecked")
    private void waitForRoles(RestClient userClient, String... roles) throws Exception {
        List<String> expected = List.of(roles);
        Object actual = null;
        for (int i = 0; i < 120; i++) {
            try {
                Response response = userClient.performRequest(new Request("GET", "/_plugins/_security/authinfo"));
                actual = asMap(response).get("roles");
                if (actual instanceof List && ((List<String>) actual).containsAll(expected)) {
                    return;
                }
            } catch (ResponseException e) {
                if (e.getResponse().getStatusLine().getStatusCode() != HttpStatus.SC_UNAUTHORIZED) {
                    throw e;
                }
            }
            Thread.sleep(500);
        }
        fail("roles " + expected + " did not become effective, got " + actual);
    }
}
