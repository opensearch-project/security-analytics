/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resthandler;

import org.junit.After;
import org.junit.Before;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.opensearch.client.Response;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.action.TestS3ConnectionRequest;
import org.opensearch.securityanalytics.action.TestS3ConnectionResponse;
import org.opensearch.securityanalytics.commons.utils.testUtils.S3ObjectGenerator;
import org.opensearch.securityanalytics.util.STIX2IOCGenerator;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.TEST_S3_CONNECTION_URI;

/**
 * The following system parameters must be specified to successfully run these tests:
 *
 * tests.TestS3ConnectionRestIT.bucketName - the name of the S3 bucket to use for the tests
 * tests.TestS3ConnectionRestIT.objectKey - OPTIONAL - the key for the bucket object we want to check
 * tests.TestS3ConnectionRestIT.region - the AWS region of the S3 bucket
 * tests.TestS3ConnectionRestIT.roleArn - the IAM role ARN to assume when making S3 calls
 *
 * The local system must have sufficient credentials to write to S3, delete from S3, and assume the provided role.
 *
 * These tests are disabled by default as there is no default value for the tests.s3connector.bucket system property. This is
 * intentional as the tests will fail when run without the proper setup, such as during CI workflows.
 *
 * Example command to manually run this class's ITs:
 * ./gradlew ':integTest' --tests "org.opensearch.securityanalytics.resthandler.TestS3ConnectionRestIT" \
 * -Dtests.TestS3ConnectionRestIT.bucketName=<BUCKET_NAME> \
 * -Dtests.TestS3ConnectionRestIT.objectKey=<OBJECT_KEY> \
 * -Dtests.TestS3ConnectionRestIT.region=<REGION> \
 * -Dtests.TestS3ConnectionRestIT.roleArn=<ROLE_ARN>
 */
@EnabledIfSystemProperty(named = "tests.TestS3ConnectionRestIT.bucketName", matches = ".+")
public class TestS3ConnectionRestIT extends SecurityAnalyticsRestTestCase {
    private String bucketName;
    private String objectKey;
    private String region;
    private String roleArn;
    private S3Client s3Client;
    private S3ObjectGenerator s3ObjectGenerator;
    private STIX2IOCGenerator stix2IOCGenerator;
    private TestS3ConnectionRequest request;
    private boolean objectKeyProvided = false;

    @Before
    public void initSource() throws IOException {
        // Retrieve system parameters needed to run the tests
        if (bucketName == null) {
            bucketName = System.getProperty("tests.TestS3ConnectionRestIT.bucketName");
            objectKey = System.getProperty("tests.TestS3ConnectionRestIT.objectKey");
            region = System.getProperty("tests.TestS3ConnectionRestIT.region");
            roleArn = System.getProperty("tests.TestS3ConnectionRestIT.roleArn");
            objectKeyProvided = objectKey != null;
        }

        // Only create the s3Client once
        if (s3Client == null) {
            s3Client = S3Client.builder()
                    .region(Region.of(region))
                    .build();
            s3ObjectGenerator = new S3ObjectGenerator(s3Client, bucketName);
        }

        // If objectKey isn't provided as system parameter, generate the objectKey in the bucket
        if (!objectKeyProvided) {
            objectKey = TestHelpers.randomLowerCaseString();
            stix2IOCGenerator = new STIX2IOCGenerator();
            s3ObjectGenerator.write(1, objectKey, stix2IOCGenerator);
        }
    }

    @After
    public void afterTest() {
        s3Client.close();
    }

    public void testConnection_succeeds() throws IOException {
        // Create the test request
        request = new TestS3ConnectionRequest(bucketName, objectKey, region, roleArn);

        // Execute test case
        Response response = makeRequest(client(), "POST", TEST_S3_CONNECTION_URI, Collections.emptyMap(), toHttpEntity(request));

        // Evaluate response
        Map<String, Object> responseBody = asMap(response);

        String status = responseBody.get(TestS3ConnectionResponse.STATUS_FIELD).toString();
        assertEquals(RestStatus.OK.name(), status);

        String error = responseBody.get(TestS3ConnectionResponse.ERROR_FIELD).toString();
        assertTrue(error.isEmpty());
    }

    public void testConnection_wrongBucket() throws IOException {
        // Create the test request
        request = new TestS3ConnectionRequest("fakebucket",  objectKey, region, roleArn);

        // Execute test case
        Response response = makeRequest(client(), "POST", TEST_S3_CONNECTION_URI, Collections.emptyMap(), toHttpEntity(request));

        // Evaluate response
        Map<String, Object> responseBody = asMap(response);

        String status = responseBody.get(TestS3ConnectionResponse.STATUS_FIELD).toString();
        assertEquals(RestStatus.MOVED_PERMANENTLY.name(), status);

        String error = responseBody.get(TestS3ConnectionResponse.ERROR_FIELD).toString();
        assertEquals("Resource not found.", error);
    }

    public void testConnection_wrongKey() throws IOException {
        // Create the test request
        request = new TestS3ConnectionRequest(bucketName, "fakekey", region, roleArn);

        // Execute test case
        Response response = makeRequest(client(), "POST", TEST_S3_CONNECTION_URI, Collections.emptyMap(), toHttpEntity(request));

        // Evaluate response
        Map<String, Object> responseBody = asMap(response);

        String status = responseBody.get(TestS3ConnectionResponse.STATUS_FIELD).toString();
        assertEquals(RestStatus.NOT_FOUND.name(), status);

        String error = responseBody.get(TestS3ConnectionResponse.ERROR_FIELD).toString();
        assertEquals("The specified key does not exist.", error);
    }

    public void testConnection_wrongRegion() throws IOException {
        // Create the test request
        String wrongRegion = (Objects.equals(region, "us-west-2")) ? "us-east-1" : "us-west-2";
        request = new TestS3ConnectionRequest(bucketName, objectKey, wrongRegion, roleArn);

        // Execute test case
        Response response = makeRequest(client(), "POST", TEST_S3_CONNECTION_URI, Collections.emptyMap(), toHttpEntity(request));

        // Evaluate response
        Map<String, Object> responseBody = asMap(response);

        String status = responseBody.get(TestS3ConnectionResponse.STATUS_FIELD).toString();
        assertEquals(RestStatus.BAD_REQUEST.name(), status);

        String error = responseBody.get(TestS3ConnectionResponse.ERROR_FIELD).toString();
        assertEquals("Resource not found.", error);
    }

    public void testConnection_invalidRegion() throws IOException {
        // Create the test request
        request = new TestS3ConnectionRequest(bucketName, objectKey, "fa-ke-1", roleArn);

        // Execute test case
        Response response = makeRequest(client(), "POST", TEST_S3_CONNECTION_URI, Collections.emptyMap(), toHttpEntity(request));

        // Evaluate response
        Map<String, Object> responseBody = asMap(response);

        String status = responseBody.get(TestS3ConnectionResponse.STATUS_FIELD).toString();
        assertEquals(RestStatus.BAD_REQUEST.name(), status);

        String error = responseBody.get(TestS3ConnectionResponse.ERROR_FIELD).toString();
        assertEquals("Resource not found.", error);
    }

    public void testConnection_wrongRoleArn() throws IOException {
        // Create the test request
        request = new TestS3ConnectionRequest(bucketName, objectKey, region, "arn:aws:iam::123456789012:role/iam-fake-role");

        // Execute test case
        Response response = makeRequest(client(), "POST", TEST_S3_CONNECTION_URI, Collections.emptyMap(), toHttpEntity(request));

        // Evaluate response
        Map<String, Object> responseBody = asMap(response);

        String status = responseBody.get(TestS3ConnectionResponse.STATUS_FIELD).toString();
        assertEquals(RestStatus.FORBIDDEN.name(), status);

        String error = responseBody.get(TestS3ConnectionResponse.ERROR_FIELD).toString();
        assertTrue(error.contains("is not authorized to perform: sts:AssumeRole on resource"));
    }

    public void testConnection_invalidRoleArn() throws IOException {
        // Create the test request
        request = new TestS3ConnectionRequest(bucketName, objectKey, region, "arn:aws:iam::12345:role/iam-invalid-role");

        // Execute test case
        Response response = makeRequest(client(), "POST", TEST_S3_CONNECTION_URI, Collections.emptyMap(), toHttpEntity(request));

        // Evaluate response
        Map<String, Object> responseBody = asMap(response);

        String status = responseBody.get(TestS3ConnectionResponse.STATUS_FIELD).toString();
        assertEquals(RestStatus.FORBIDDEN.name(), status);

        String error = responseBody.get(TestS3ConnectionResponse.ERROR_FIELD).toString();
        assertTrue(error.contains("is not authorized to perform: sts:AssumeRole on resource"));
    }
}
