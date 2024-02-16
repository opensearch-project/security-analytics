package org.opensearch.securityanalytics.resthandler;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class SecureExecuteStreamingDetectorsRestApiIT extends SecurityAnalyticsRestTestCase {
    private static final String TEST_INDEX = "test-streaming-detectors";
    private static final String BULK_REQUEST_STRING = "{\"index\":{\"_index\":\"" + TEST_INDEX + "\"}}\n" +
            "{\"test\":\"doc\"}\n";
    private static final String READ_ONLY_ROLE = "readall";

    public void testExecuteStreamingDetectorsWithSecurityEnabled_AllowAdminUser() throws IOException {
        try (RestClient restClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), "admin", "admin")
                .setSocketTimeout(60000).build()) {
            final Response response = restClient.performRequest(getLowLevelBulkRequest());
            assertEquals(RestStatus.OK.getStatus(), response.getStatusLine().getStatusCode());
        }
    }

    public void testExecuteStreamingDetectorsWithSecurityEnabled_AllowUserAttachedToAdminBackendRole() throws IOException {
        final String anotherAdminUser = "executeStreamingDetectorsAnotherAdminUser";
        final String[] backendRoles = { "admin" };
        createUser(anotherAdminUser, backendRoles);
        try (RestClient restClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), anotherAdminUser, password)
                .setSocketTimeout(60000).build()) {
            final Response response = restClient.performRequest(getLowLevelBulkRequest());
            assertEquals(RestStatus.OK.getStatus(), response.getStatusLine().getStatusCode());
        }
    }

    public void testExecuteStreamingDetectorsWithSecurityEnabled_RejectNonAdminUser() throws IOException {
        final String notAdminUser = "executeStreamingDetectorsNotAdminUser";
        final String[] backendRoles = {};
        createUserWithData(notAdminUser, notAdminUser, READ_ONLY_ROLE, backendRoles );

        try (RestClient restClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), notAdminUser, password)
                .setSocketTimeout(60000).build()) {
            restClient.performRequest(getLowLevelBulkRequest());
            // Ensure above request threw an exception by failing if we reach the next line
            fail();
        } catch (ResponseException e) {
            assertEquals(RestStatus.FORBIDDEN.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        } finally {
            deleteUser(notAdminUser);
        }
    }

    public void testExecuteStreamingDetectorsWithSecurityEnabled_RejectUnauthorizedUser() throws IOException {
        try (RestClient restClient = new SecureRestClientBuilder(getClusterHosts().toArray(new HttpHost[]{}), isHttps(), UUID.randomUUID().toString(), password)
                .setSocketTimeout(60000).build()) {
            restClient.performRequest(getLowLevelBulkRequest());
            // Ensure above request threw an exception by failing if we reach the next line
            fail();
        } catch (ResponseException e) {
            assertEquals(RestStatus.UNAUTHORIZED.getStatus(), e.getResponse().getStatusLine().getStatusCode());
        }
    }

    private Request getLowLevelBulkRequest() {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(BULK_REQUEST_STRING.getBytes(StandardCharsets.UTF_8));
        final HttpEntity httpEntity = new ByteArrayEntity(byteArrayOutputStream.toByteArray(), ContentType.APPLICATION_JSON);

        final Request request = new Request("POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/streaming/execute");
        request.setOptions(RequestOptions.DEFAULT);
        request.setEntity(httpEntity);

        return request;
    }
}
