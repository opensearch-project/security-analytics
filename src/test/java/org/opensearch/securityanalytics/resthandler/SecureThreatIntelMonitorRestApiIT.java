package org.opensearch.securityanalytics.resthandler;

import org.apache.hc.core5.http.HttpHost;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.threatIntel.common.RefreshType;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigType;
import org.opensearch.securityanalytics.threatIntel.common.TIFJobState;
import org.opensearch.securityanalytics.threatIntel.model.DefaultIocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;
import static org.opensearch.securityanalytics.resthandler.ThreatIntelMonitorRestApiIT.randomIocScanMonitorDto;

public class SecureThreatIntelMonitorRestApiIT extends SecurityAnalyticsRestTestCase {
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
        String[] backendRoles = {TEST_HR_BACKEND_ROLE};
        createUserWithData(user, user, SECURITY_ANALYTICS_FULL_ACCESS_ROLE, backendRoles);
        if (userClient == null) {
            userClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), user, password).setSocketTimeout(60000).build();
        }
    }

    @After
    public void cleanup() throws IOException {
        if (userClient != null) {
            userClient.close();
        }
        deleteUser(user);
    }

    private final String iocIndexMappings = "\"properties\": {\n" +
            "    \"stix2_ioc\": {\n" +
            "      \"properties\": {\n" +
            "        \"name\": {\n" +
            "          \"type\": \"keyword\"\n" +
            "        },\n" +
            "        \"type\": {\n" +
            "          \"type\": \"keyword\"\n" +
            "        },\n" +
            "        \"value\": {\n" +
            "          \"type\": \"keyword\"\n" +
            "        },\n" +
            "        \"severity\": {\n" +
            "          \"type\": \"keyword\"\n" +
            "        },\n" +
            "        \"spec_version\": {\n" +
            "          \"type\": \"keyword\"\n" +
            "        },\n" +
            "        \"created\": {\n" +
            "          \"type\": \"date\"\n" +
            "        },\n" +
            "        \"modified\": {\n" +
            "          \"type\": \"date\"\n" +
            "        },\n" +
            "        \"description\": {\n" +
            "          \"type\": \"text\"\n" +
            "        },\n" +
            "        \"labels\": {\n" +
            "          \"type\": \"keyword\"\n" +
            "        },\n" +
            "        \"feed_id\": {\n" +
            "          \"type\": \"keyword\"\n" +
            "        },\n" +
            "        \"feed_name\": {\n" +
            "          \"type\": \"keyword\"\n" +
            "        }\n" +
            "      }\n" +
            "    }\n" +
            "  }";

    private List<STIX2IOC> testIocs = new ArrayList<>();

    public void indexSourceConfigsAndIocs(int num, List<String> iocVals) throws IOException {
        for (int i = 0; i < num; i++) {
            String configId = "id" + i;
            String iocActiveIndex = ".opensearch-sap-ioc-" + configId + Instant.now().toEpochMilli();
            String indexPattern = ".opensearch-sap-ioc-" + configId;
            indexTifSourceConfig(num, configId, indexPattern, iocActiveIndex, i);

            // Create the index before ingesting docs to ensure the mappings are correct
            createIndex(iocActiveIndex, Settings.EMPTY, iocIndexMappings);

            // Refresh testIocs list between tests
            testIocs = new ArrayList<>();
            for (int i1 = 0; i1 < iocVals.size(); i1++) {
                indexIocs(iocVals, iocActiveIndex, i1, configId);
            }
        }
    }

    private void indexIocs(List<String> iocVals, String iocIndexName, int i1, String configId) throws IOException {
        String iocId = iocIndexName + i1;
        STIX2IOC stix2IOC = new STIX2IOC(
                iocId,
                "random",
                new IOCType(IOCType.IPV4_TYPE),
                iocVals.get(i1),
                "",
                Instant.now(),
                Instant.now(),
                "",
                emptyList(),
                "spec",
                configId,
                "",
                STIX2IOC.NO_VERSION
        );

        // Add IOC to testIocs List for future validation
        testIocs.add(stix2IOC);

        indexDoc(iocIndexName, iocId, stix2IOC.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS).toString());
        List<SearchHit> searchHits = executeSearch(iocIndexName, getMatchAllSearchRequestString(iocVals.size()));
        assertEquals(searchHits.size(), i1 + 1);
    }

    private void indexTifSourceConfig(int num, String configId, String indexPattern, String iocActiveIndex, int i) throws IOException {
        SATIFSourceConfig config = new SATIFSourceConfig(
                configId,
                SATIFSourceConfig.NO_VERSION,
                "name1",
                "STIX2",
                SourceConfigType.S3_CUSTOM,
                "description",
                null,
                Instant.now(),
                new S3Source("bucketname", "key", "region", "roleArn"),
                null,
                Instant.now(),
                new org.opensearch.jobscheduler.spi.schedule.IntervalSchedule(Instant.now(), 1, ChronoUnit.MINUTES),
                TIFJobState.AVAILABLE,
                RefreshType.FULL,
                null,
                null,
                false,
                new DefaultIocStoreConfig(List.of(new DefaultIocStoreConfig.IocToIndexDetails(new IOCType(IOCType.IPV4_TYPE), indexPattern, iocActiveIndex))),
                List.of(IOCType.IPV4_TYPE),
                true
        );
        String indexName = SecurityAnalyticsPlugin.JOB_INDEX_NAME;
        Response response = indexDoc(indexName, configId, config.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS).toString());
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
            indexSourceConfigsAndIocs(1, vals);
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
