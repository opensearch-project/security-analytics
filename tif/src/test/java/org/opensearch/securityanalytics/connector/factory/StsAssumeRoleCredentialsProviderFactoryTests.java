package org.opensearch.securityanalytics.connector.factory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class StsAssumeRoleCredentialsProviderFactoryTests {
    private static final String REGION = UUID.randomUUID().toString();
    private static final String ROLE_ARN = "arn:aws:iam::123456789012:role/" + UUID.randomUUID();

    @Mock
    private StsClientFactory stsClientFactory;
    @Mock
    private StsClient stsClient;

    private StsAssumeRoleCredentialsProviderFactory stsAssumeRoleCredentialsProviderFactory;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        this.stsAssumeRoleCredentialsProviderFactory = new StsAssumeRoleCredentialsProviderFactory(stsClientFactory);
    }

    @AfterEach
    public void teardown() {
        verifyNoMoreInteractions(stsClientFactory, stsClient);
    }

    @Test
    public void testDoCreate() {
        when(stsClientFactory.create(eq(REGION))).thenReturn(stsClient);

        assertInstanceOf(StsAssumeRoleCredentialsProvider.class, stsAssumeRoleCredentialsProviderFactory.doCreate(ROLE_ARN, REGION));

        verify(stsClientFactory).create(eq(REGION));
    }

    @Test
    public void testDoCreate_ExceptionCreatingStsClient() {
        when(stsClientFactory.create(eq(REGION))).thenThrow(new RuntimeException());

        assertThrows(RuntimeException.class, () -> stsAssumeRoleCredentialsProviderFactory.doCreate(ROLE_ARN, REGION));

        verify(stsClientFactory).create(eq(REGION));
    }

    @Test
    public void testDoCreate_MalformedArn() {
        final String roleArn = UUID.randomUUID().toString();
        when(stsClientFactory.create(eq(REGION))).thenReturn(stsClient);

        assertThrows(IllegalArgumentException.class, () -> stsAssumeRoleCredentialsProviderFactory.doCreate(roleArn, REGION));
    }

    @Test
    public void testDoCreate_NotIamService() {
        final String roleArn = "arn:aws:ecs::123456789012:role/" + UUID.randomUUID();
        when(stsClientFactory.create(eq(REGION))).thenReturn(stsClient);

        assertThrows(IllegalArgumentException.class, () -> stsAssumeRoleCredentialsProviderFactory.doCreate(roleArn, REGION));
    }

    @Test
    public void testDoCreate_NotRoleResource() {
        final String roleArn = "arn:aws:iam::123456789012:task/" + UUID.randomUUID();
        when(stsClientFactory.create(eq(REGION))).thenReturn(stsClient);

        assertThrows(IllegalArgumentException.class, () -> stsAssumeRoleCredentialsProviderFactory.doCreate(roleArn, REGION));
    }

    @Test
    public void testDoCreate_EmptyResource() {
        final String roleArn = "arn:aws:iam::123456789012:/" + UUID.randomUUID();
        when(stsClientFactory.create(eq(REGION))).thenReturn(stsClient);

        assertThrows(IllegalArgumentException.class, () -> stsAssumeRoleCredentialsProviderFactory.doCreate(roleArn, REGION));
    }
}
