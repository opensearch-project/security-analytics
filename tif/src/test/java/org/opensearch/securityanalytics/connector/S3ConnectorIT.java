package org.opensearch.securityanalytics.connector;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.opensearch.securityanalytics.connector.factory.InputCodecFactory;
import org.opensearch.securityanalytics.connector.factory.S3ClientFactory;
import org.opensearch.securityanalytics.connector.factory.StsAssumeRoleCredentialsProviderFactory;
import org.opensearch.securityanalytics.connector.factory.StsClientFactory;
import org.opensearch.securityanalytics.connector.model.InputCodecSchema;
import org.opensearch.securityanalytics.connector.model.S3ConnectorConfig;
import org.opensearch.securityanalytics.connector.util.NewlineDelimitedIOCGenerator;
import org.opensearch.securityanalytics.connector.util.S3ObjectGenerator;
import org.opensearch.securityanalytics.model.IOC;
import org.opensearch.securityanalytics.model.IOCSchema;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.sts.model.StsException;

import java.io.IOException;
import java.util.List;
import java.util.Random;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Integration test class for the S3 connector. The following system parameters must be specified to successfully run the tests:
 *
 * tests.s3connector.bucket - the name of the S3 bucket to use for the tests
 * tests.s3connector.region - the AWS region of the S3 bucket
 * tests.s3connector.roleArn - the IAM role ARN to assume when making S3 calls
 *
 * The local system must have sufficient credentials to write to S3, delete from S3, and assume the provided role.
 *
 * The tests are disabled by default as there is no default value for the tests.s3connector.bucket system property. This is
 * intentional as the tests will fail when run without the proper setup, such as during CI workflows.
 *
 * Example command to manually run this class's ITs:
 * ./gradlew :tif:s3ConnectorIT -Dtests.s3connector.bucket=<BUCKET_NAME> -Dtests.s3connector.region=<REGION> -Dtests.s3connector.roleArn=<ROLE_ARN>
 */
@EnabledIfSystemProperty(named = "tests.s3connector.bucket", matches = ".+")
public class S3ConnectorIT {
    private static final String FEED_ID = UUID.randomUUID().toString();
    private static final int NUMBER_OF_IOCS = new Random().nextInt(100);

    private S3Client s3Client;
    private S3ObjectGenerator s3ObjectGenerator;
    private String bucket;
    private String region;
    private String roleArn;

    @BeforeEach
    public void setup() {
        region = System.getProperty("tests.s3connector.region");
        roleArn = System.getProperty("tests.s3connector.roleArn");
        bucket = System.getProperty("tests.s3connector.bucket");

        s3Client = S3Client.builder()
                .region(Region.of(region))
                .build();
        s3ObjectGenerator = new S3ObjectGenerator(s3Client, bucket);
    }

    private S3Connector createS3Connector(final S3ConnectorConfig s3ConnectorConfig) {
        final StsClientFactory stsClientFactory = new StsClientFactory();
        final StsAssumeRoleCredentialsProviderFactory stsAssumeRoleCredentialsProviderFactory = new StsAssumeRoleCredentialsProviderFactory(stsClientFactory);
        final S3ClientFactory s3ClientFactory = new S3ClientFactory(stsAssumeRoleCredentialsProviderFactory);
        final InputCodecFactory inputCodecFactory = new InputCodecFactory();

        return new S3Connector(s3ConnectorConfig, s3ClientFactory, inputCodecFactory);
    }

    @Test
    public void testS3Connector_Success() throws IOException {
        final String objectKey = UUID.randomUUID().toString();
        s3ObjectGenerator.write(NUMBER_OF_IOCS, objectKey, new NewlineDelimitedIOCGenerator());

        final S3ConnectorConfig s3ConnectorConfig = new S3ConnectorConfig(
                bucket,
                objectKey,
                region,
                roleArn,
                IOCSchema.STIX2,
                InputCodecSchema.ND_JSON,
                FEED_ID
        );
        final S3Connector s3Connector = createS3Connector(s3ConnectorConfig);

        final List<IOC> iocs = s3Connector.loadIOCs();
        assertEquals(NUMBER_OF_IOCS, iocs.size());

        deleteObject(objectKey);
    }

    @Test
    public void testS3Connector_BucketDoesNotExist() {
        final String objectKey = UUID.randomUUID().toString();
        final S3ConnectorConfig s3ConnectorConfig = new S3ConnectorConfig(
                UUID.randomUUID().toString(),
                objectKey,
                region,
                roleArn,
                IOCSchema.STIX2,
                InputCodecSchema.ND_JSON,
                FEED_ID
        );
        final S3Connector s3Connector = createS3Connector(s3ConnectorConfig);

        assertThrows(NoSuchBucketException.class, s3Connector::loadIOCs);
    }

    @Test
    public void testS3Connector_ObjectDoesNotExist() {
        final S3ConnectorConfig s3ConnectorConfig = new S3ConnectorConfig(
                bucket,
                UUID.randomUUID().toString(),
                region,
                roleArn,
                IOCSchema.STIX2,
                InputCodecSchema.ND_JSON,
                FEED_ID
        );
        final S3Connector s3Connector = createS3Connector(s3ConnectorConfig);

        assertThrows(NoSuchKeyException.class, s3Connector::loadIOCs);
    }

    @Test
    public void testS3Connector_InvalidRegion() {
        final String objectKey = UUID.randomUUID().toString();
        final S3ConnectorConfig s3ConnectorConfig = new S3ConnectorConfig(
                bucket,
                objectKey,
                UUID.randomUUID().toString(),
                roleArn,
                IOCSchema.STIX2,
                InputCodecSchema.ND_JSON,
                FEED_ID
        );
        final S3Connector s3Connector = createS3Connector(s3ConnectorConfig);

        assertThrows(SdkClientException.class, s3Connector::loadIOCs);
    }

    @Test
    public void testS3Connector_FailToAssumeRule() {
        final String objectKey = UUID.randomUUID().toString();
        final S3ConnectorConfig s3ConnectorConfig = new S3ConnectorConfig(
                bucket,
                objectKey,
                region,
                roleArn + UUID.randomUUID(),
                IOCSchema.STIX2,
                InputCodecSchema.ND_JSON,
                FEED_ID
        );
        final S3Connector s3Connector = createS3Connector(s3ConnectorConfig);

        assertThrows(StsException.class, s3Connector::loadIOCs);
    }

    private void deleteObject(final String objectKey) {
        final DeleteObjectRequest deleteObjectRequest = DeleteObjectRequest.builder()
                .bucket(bucket)
                .key(objectKey)
                .build();
        s3Client.deleteObject(deleteObjectRequest);
    }
}
