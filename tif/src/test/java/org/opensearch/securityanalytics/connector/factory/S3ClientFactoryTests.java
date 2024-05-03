package org.opensearch.securityanalytics.connector.factory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.s3.S3Client;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class S3ClientFactoryTests {
    private static final String REGION = UUID.randomUUID().toString();
    private static final String ROLE_ARN = UUID.randomUUID().toString();

    @Mock
    private StsAssumeRoleCredentialsProviderFactory stsAssumeRoleCredentialsProviderFactory;
    @Mock
    private AwsCredentialsProvider awsCredentialsProvider;

    private S3ClientFactory s3ClientFactory;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        s3ClientFactory = new S3ClientFactory(stsAssumeRoleCredentialsProviderFactory);
    }

    @AfterEach
    public void teardown() {
        verifyNoMoreInteractions(stsAssumeRoleCredentialsProviderFactory, awsCredentialsProvider);
    }

    @Test
    public void testDoCreate() {
        when(stsAssumeRoleCredentialsProviderFactory.create(eq(ROLE_ARN), eq(REGION))).thenReturn(awsCredentialsProvider);

        assertInstanceOf(S3Client.class, s3ClientFactory.doCreate(ROLE_ARN, REGION));

        verify(stsAssumeRoleCredentialsProviderFactory).create(eq(ROLE_ARN), eq(REGION));
    }

    @Test
    public void testDoCreate_ExceptionGettingCredentialsProvider() {
        when(stsAssumeRoleCredentialsProviderFactory.create(eq(ROLE_ARN), eq(REGION))).thenThrow(new RuntimeException());

        assertThrows(RuntimeException.class, () -> s3ClientFactory.doCreate(ROLE_ARN, REGION));

        verify(stsAssumeRoleCredentialsProviderFactory).create(eq(ROLE_ARN), eq(REGION));
    }
}
