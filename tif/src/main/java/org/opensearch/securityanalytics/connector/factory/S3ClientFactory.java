package org.opensearch.securityanalytics.connector.factory;

import org.opensearch.securityanalytics.factory.BinaryParameterCachingFactory;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

public class S3ClientFactory extends BinaryParameterCachingFactory<String, String, S3Client> {
    private final StsAssumeRoleCredentialsProviderFactory stsAssumeRoleCredentialsProviderFactory;

    public S3ClientFactory(final StsAssumeRoleCredentialsProviderFactory stsAssumeRoleCredentialsProviderFactory) {
        super();
        this.stsAssumeRoleCredentialsProviderFactory = stsAssumeRoleCredentialsProviderFactory;
    }

    @Override
    protected S3Client doCreate(final String roleArn, final String region) {
        final AwsCredentialsProvider credentialsProvider = stsAssumeRoleCredentialsProviderFactory.create(roleArn, region);
        return S3Client.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.of(region))
                .build();
    }
}
