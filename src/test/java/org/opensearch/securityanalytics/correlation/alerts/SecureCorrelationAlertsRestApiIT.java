package org.opensearch.securityanalytics.correlation.alerts;

import org.apache.hc.core5.http.HttpHost;
import org.junit.After;
import org.junit.Before;
import org.opensearch.client.RestClient;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import java.io.IOException;

public class SecureCorrelationAlertsRestApiIT  extends SecurityAnalyticsRestTestCase {
    static String SECURITY_ANALYTICS_FULL_ACCESS_ROLE = "security_analytics_full_access";
    static String SECURITY_ANALYTICS_READ_ACCESS_ROLE = "security_analytics_read_access";
    static String TEST_HR_BACKEND_ROLE = "HR";
    static String TEST_IT_BACKEND_ROLE = "IT";
    private final String user = "userAlert";
    private static final String[] EMPTY_ARRAY = new String[0];
    private RestClient userClient;

    @Before
    public void create() throws IOException {
        String[] backendRoles = { TEST_HR_BACKEND_ROLE };
        createUserWithData(user, user, SECURITY_ANALYTICS_FULL_ACCESS_ROLE, backendRoles );
        if (userClient == null) {
            userClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), user, password).setSocketTimeout(60000).build();
        }
    }

    @After
    public void cleanup() throws IOException {
        userClient.close();
        deleteUser(user);
    }

    /*** TODO **/
    public void testGetCorrelationAlertsAPI() throws IOException, InterruptedException {}

}
