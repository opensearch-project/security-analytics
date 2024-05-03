/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.connector.factory;

import org.opensearch.securityanalytics.factory.BinaryParameterCachingFactory;
import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

import java.util.Optional;
import java.util.UUID;

public class StsAssumeRoleCredentialsProviderFactory extends BinaryParameterCachingFactory<String, String, AwsCredentialsProvider> {
    private static final String AWS_IAM = "iam";
    private static final String AWS_IAM_ROLE = "role";

    private final StsClientFactory stsClientFactory;

    public StsAssumeRoleCredentialsProviderFactory(final StsClientFactory stsClientFactory) {
        super();
        this.stsClientFactory = stsClientFactory;
    }

    @Override
    protected AwsCredentialsProvider doCreate(final String stsRoleArn, final String region) {
        validateStsRoleArn(stsRoleArn);

        final AssumeRoleRequest.Builder assumeRoleRequestBuilder = AssumeRoleRequest.builder()
                .roleSessionName("TIF-" + UUID.randomUUID())
                .roleArn(stsRoleArn);
        final StsClient stsClient = stsClientFactory.create(region);

        return StsAssumeRoleCredentialsProvider.builder()
                .stsClient(stsClient)
                .refreshRequest(assumeRoleRequestBuilder.build())
                .build();
    }

    private void validateStsRoleArn(final String stsRoleArn) {
        final Arn arn = getArn(stsRoleArn);
        if (!AWS_IAM.equals(arn.service())) {
            throw new IllegalArgumentException("roleArn must be an IAM Role");
        }
        final Optional<String> resourceType = arn.resource().resourceType();
        if (resourceType.isEmpty() || !resourceType.get().equals(AWS_IAM_ROLE)) {
            throw new IllegalArgumentException("roleArn must be an IAM Role");
        }
    }

    private Arn getArn(final String stsRoleArn) {
        try {
            return Arn.fromString(stsRoleArn);
        } catch (final Exception e) {
            throw new IllegalArgumentException(String.format("Invalid ARN format for roleArn. Check the format of %s", stsRoleArn));
        }
    }
}
