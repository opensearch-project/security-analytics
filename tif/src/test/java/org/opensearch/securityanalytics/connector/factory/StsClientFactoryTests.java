/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.connector.factory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.sts.StsClient;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class StsClientFactoryTests {
    private StsClientFactory stsClientFactory;

    @BeforeEach
    public void setup() {
        stsClientFactory = new StsClientFactory();
    }

    @Test
    public void testDoCreate() {
        assertInstanceOf(StsClient.class, stsClientFactory.doCreate(UUID.randomUUID().toString()));
    }
}
