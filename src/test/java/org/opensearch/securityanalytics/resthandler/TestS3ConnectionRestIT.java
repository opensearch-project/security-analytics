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
 * -Dtests.TestS3ConnectionRestIT.objectKey=<BUCKET_NAME> \
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

    public void testConnectionSucceeds() throws IOException {
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

    // TODO implement more integ test cases
}
