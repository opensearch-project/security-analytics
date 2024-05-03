/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.connector;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.securityanalytics.connector.codec.InputCodec;
import org.opensearch.securityanalytics.connector.factory.InputCodecFactory;
import org.opensearch.securityanalytics.connector.factory.S3ClientFactory;
import org.opensearch.securityanalytics.connector.model.S3ConnectorConfig;
import org.opensearch.securityanalytics.model.IOC;
import org.opensearch.securityanalytics.model.IOCSchema;
import org.opensearch.securityanalytics.connector.model.InputCodecSchema;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class S3ConnectorTests {
    private static final String BUCKET_NAME = UUID.randomUUID().toString();
    private static final String OBJECT_KEY = UUID.randomUUID().toString();
    private static final String REGION = UUID.randomUUID().toString();
    private static final String ROLE_ARN = UUID.randomUUID().toString();
    private static final IOCSchema IOC_SCHEMA = IOCSchema.STIX2;
    private static final InputCodecSchema INPUT_CODEC_SCHEMA = InputCodecSchema.ND_JSON;
    private static final S3ConnectorConfig S3_CONNECTOR_CONFIG = new S3ConnectorConfig(
            BUCKET_NAME,
            OBJECT_KEY,
            REGION,
            ROLE_ARN,
            IOC_SCHEMA,
            INPUT_CODEC_SCHEMA
    );

    @Mock
    private S3ClientFactory s3ClientFactory;
    @Mock
    private S3Client s3Client;
    @Mock
    private InputCodecFactory inputCodecFactory;
    @Mock
    private InputCodec inputCodec;
    @Mock
    private ResponseInputStream<GetObjectResponse> responseInputStream;
    @Mock
    private IOC ioc;

    private S3Connector s3Connector;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        when(s3ClientFactory.create(eq(ROLE_ARN), eq(REGION))).thenReturn(s3Client);
        when(inputCodecFactory.create(eq(INPUT_CODEC_SCHEMA), eq(IOC_SCHEMA))).thenReturn(inputCodec);

        this.s3Connector = new S3Connector(S3_CONNECTOR_CONFIG, s3ClientFactory, inputCodecFactory);
    }

    @AfterEach
    public void tearDown() {
        verify(s3ClientFactory).create(eq(ROLE_ARN), eq(REGION));
        verify(inputCodecFactory).create(eq(INPUT_CODEC_SCHEMA), eq(IOC_SCHEMA));

        verifyNoMoreInteractions(s3ClientFactory, inputCodecFactory, s3Client, inputCodec, responseInputStream);
    }

    @Test
    public void testLoadIOCs() {
        when(s3Client.getObject(any(GetObjectRequest.class))).thenReturn(responseInputStream);
        when(inputCodec.parse(eq(responseInputStream))).thenReturn(List.of(ioc));

        assertEquals(List.of(ioc), s3Connector.loadIOCs());

        final ArgumentCaptor<GetObjectRequest> argumentCaptor = ArgumentCaptor.forClass(GetObjectRequest.class);
        verify(s3Client).getObject(argumentCaptor.capture());
        verify(inputCodec).parse(eq(responseInputStream));

        assertEquals(OBJECT_KEY, argumentCaptor.getValue().key());
        assertEquals(BUCKET_NAME, argumentCaptor.getValue().bucket());
    }

    @Test
    public void testLoadIOCs_ExceptionGettingObject() {
        when(s3Client.getObject(any(GetObjectRequest.class))).thenThrow(new RuntimeException());

        assertThrows(RuntimeException.class, () -> s3Connector.loadIOCs());

        final ArgumentCaptor<GetObjectRequest> argumentCaptor = ArgumentCaptor.forClass(GetObjectRequest.class);
        verify(s3Client).getObject(argumentCaptor.capture());

        assertEquals(OBJECT_KEY, argumentCaptor.getValue().key());
        assertEquals(BUCKET_NAME, argumentCaptor.getValue().bucket());
    }

    @Test
    public void testLoadIOCs_ExceptionParsingObject() {
        when(s3Client.getObject(any(GetObjectRequest.class))).thenReturn(responseInputStream);
        when(inputCodec.parse(eq(responseInputStream))).thenThrow(new RuntimeException());

        assertThrows(RuntimeException.class, () -> s3Connector.loadIOCs());

        final ArgumentCaptor<GetObjectRequest> argumentCaptor = ArgumentCaptor.forClass(GetObjectRequest.class);
        verify(s3Client).getObject(argumentCaptor.capture());
        verify(inputCodec).parse(eq(responseInputStream));

        assertEquals(OBJECT_KEY, argumentCaptor.getValue().key());
        assertEquals(BUCKET_NAME, argumentCaptor.getValue().bucket());
    }
}
