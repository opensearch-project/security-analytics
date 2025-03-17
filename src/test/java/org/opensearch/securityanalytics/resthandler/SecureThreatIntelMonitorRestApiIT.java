package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.HttpHost;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;
import static org.opensearch.securityanalytics.resthandler.ThreatIntelMonitorRestApiIT.randomIocScanMonitorDto;

public class SecureThreatIntelMonitorRestApiIT extends SecurityAnalyticsRestTestCase {
    static String SECURITY_ANALYTICS_FULL_ACCESS_ROLE = "security_analytics_full_access";
    static String SECURITY_ANALYTICS_READ_ACCESS_ROLE = "security_analytics_read_access";
    static String TEST_HR_BACKEND_ROLE = "HR";

    static String TEST_IT_BACKEND_ROLE = "IT";

    private RestClient userClient;
    private final String user = "threatIntelUser";

    @Before
    public void create() throws IOException {
        try {
            // TODO hurneyt
            Response response = makeRequest(client(), "GET", "/_cat/tasks?v&format=json", Collections.emptyMap(), null);
            logger.info("hurneyt SecureThreatIntelMonitorRestApiIT cat/tasks RESPONSE {}", asMap(response));
        } catch (Exception e) {
            logger.info("hurneyt SecureThreatIntelMonitorRestApiIT cat/tasks FAILED {}", e);
        }

        try {
            // TODO hurneyt
            Response response = makeRequest(client(), "POST", "/_tasks/_cancel?actions=*/alerting/*", Collections.emptyMap(), null);
            logger.info("hurneyt SecureThreatIntelMonitorRestApiIT task cancel RESPONSE {}", asMap(response));
        } catch (Exception e) {
            logger.info("hurneyt SecureThreatIntelMonitorRestApiIT task cancel FAILED {}", e);
        }

        try {
            // TODO hurneyt
            Response response = makeRequest(client(), "DELETE", ".*alerting*,.*sap*", Collections.emptyMap(), null);
            logger.info("hurneyt SecureThreatIntelMonitorRestApiIT delete RESPONSE {}", asMap(response));
            client().wait(10000);
        } catch (Exception e) {
            logger.info("hurneyt SecureThreatIntelMonitorRestApiIT delete FAILED {}", e);
        }

        String[] backendRoles = {TEST_HR_BACKEND_ROLE};
        createUserWithData(user, user, SECURITY_ANALYTICS_FULL_ACCESS_ROLE, backendRoles);
        if (userClient == null) {
            userClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), user, password).setSocketTimeout(60000).build();
        }
    }

    @After
    public void cleanup() throws IOException {
        userClient.close();
        deleteUser(user);
    }


    public void testCreateThreatIntelMonitorWithNoBackendRoles() throws IOException {
        // try to do create detector as a user with no backend roles
        String userFull = "userFull";
        String[] backendRoles = {};
        createUserWithData(userFull, userFull, SECURITY_ANALYTICS_FULL_ACCESS_ROLE, backendRoles);
        RestClient userFullClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userFull, password).setSocketTimeout(60000).build();
        String index = createTestIndex(randomIndex(), windowsIndexMapping());
        // Enable backend filtering and try to read detector as a user with no backend roles matching the user who created the detector
        enableOrDisableFilterBy("true");
        try {
            ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDto(index);
            Response response = makeRequest(userClient, "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
            fail("Command to create monitor by user client without backend roles should not have succeeded.");
        } catch (ResponseException e) {
            assertEquals("Create detector failed", RestStatus.FORBIDDEN, restStatus(e.getResponse()));
        } finally {
            userFullClient.close();
            deleteUser(userFull);
        }
    }

    public void testCreateThreatIntelMonitorWithFullAccess() throws IOException {
        try {
            String index = createTestIndex(randomIndex(), windowsIndexMapping());
            // Assign a role to the index
            createIndexRole(TEST_HR_ROLE, Collections.emptyList(), indexPermissions, List.of(index));
            String[] users = {user};
            // Assign a role to existing user
            createUserRolesMapping(TEST_HR_ROLE, users);
            Response iocFindingsResponse = makeRequest(userClient, "GET", SecurityAnalyticsPlugin.THREAT_INTEL_BASE_URI + "/findings/_search",
                    Map.of(), null);
            Map<String, Object> responseAsMap = responseAsMap(iocFindingsResponse);
            Assert.assertEquals(0, ((List<Map<String, Object>>) responseAsMap.get("ioc_findings")).size());
            List<String> vals = List.of("ip1", "ip2");
            String monitorName = "test_monitor_name";


            /**create monitor */
            ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDto(index);
            Response response = makeRequest(userClient, "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
            Assert.assertEquals(201, response.getStatusLine().getStatusCode());
            Map<String, Object> responseBody = asMap(response);
            final String monitorId = responseBody.get("id").toString();
            Assert.assertNotEquals("response is missing Id", Monitor.NO_ID, monitorId);

            try {
                makeRequest(userClient, "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
                fail();
            } catch (Exception e) {
                /** creating a second threat intel monitor should fail*/
                assertTrue(e.getMessage().contains("already exists"));
            }

        } finally {
            tryDeletingRole(TEST_HR_ROLE);
        }
    }

    public void testCreateMonitor_userHasIndexAccess_success() throws IOException {
        String[] backendRoles = {TEST_IT_BACKEND_ROLE};
        String userWithAccess = "user1";
        String roleNameWithIndexPatternAccess = "test-role-1";
        String windowsIndexPattern = "windows*";
        createUserWithDataAndCustomRole(userWithAccess, userWithAccess, roleNameWithIndexPatternAccess, backendRoles, clusterPermissions, indexPermissions, List.of(windowsIndexPattern));
        RestClient clientWithAccess = null;
        try {
            clientWithAccess = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), userWithAccess, password).setSocketTimeout(60000).build();
            String index = createTestIndex(client(), randomIndex(), windowsIndexMapping(), Settings.EMPTY);
            ThreatIntelMonitorDto iocScanMonitor = randomIocScanMonitorDto(index);
            Response response = makeRequest(clientWithAccess, "POST", SecurityAnalyticsPlugin.THREAT_INTEL_MONITOR_URI, Collections.emptyMap(), toHttpEntity(iocScanMonitor));
            Assert.assertEquals(201, response.getStatusLine().getStatusCode());
            Map<String, Object> responseBody = asMap(response);
            final String monitorId = responseBody.get("id").toString();
            Assert.assertNotEquals("response is missing Id", Monitor.NO_ID, monitorId);
        } finally {
            if (clientWithAccess != null) clientWithAccess.close();
            deleteUser(userWithAccess);
            tryDeletingRole(roleNameWithIndexPatternAccess);
        }
    }

    protected void createUserWithData(String userName, String userPasswd, String roleName, String[] backendRoles) throws IOException {
        String[] users = {userName};
        createUser(userName, backendRoles);
        createUserRolesMapping(roleName, users);
    }

    public void createUserWithTestData(String user, String index, String role, String[] backendRoles, List<String> indexPermissions) throws IOException {
        String[] users = {user};
        createUser(user, backendRoles);
        createTestIndex(client(), index, windowsIndexMapping(), Settings.EMPTY);
        createIndexRole(role, Collections.emptyList(), indexPermissions, List.of(index));
        createUserRolesMapping(role, users);
    }

}
