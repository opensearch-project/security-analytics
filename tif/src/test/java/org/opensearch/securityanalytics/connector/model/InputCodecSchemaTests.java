/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.connector.model;

import org.junit.jupiter.api.Test;
import org.opensearch.securityanalytics.connector.codec.NewlineDelimitedJsonCodecTests;
import org.opensearch.securityanalytics.model.IOCSchema;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class InputCodecSchemaTests {
    @Test
    public void testGetInputCodecConstructor_ND_JSON() {
        assertInstanceOf(NewlineDelimitedJsonCodecTests.class, InputCodecSchema.ND_JSON.getInputCodecConstructor().apply(IOCSchema.STIX2));
    }
}
