/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.connector.factory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensearch.securityanalytics.connector.codec.NewlineDelimitedJsonCodecTests;
import org.opensearch.securityanalytics.connector.model.InputCodecSchema;
import org.opensearch.securityanalytics.model.IOCSchema;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class InputCodecFactoryTests {
    private InputCodecFactory inputCodecFactory;

    @BeforeEach
    public void setup() {
        inputCodecFactory = new InputCodecFactory();
    }

    @Test
    public void testDoCreate_ND_JSON() {
        assertInstanceOf(NewlineDelimitedJsonCodecTests.class, inputCodecFactory.doCreate(InputCodecSchema.ND_JSON, IOCSchema.STIX2));
    }
}
