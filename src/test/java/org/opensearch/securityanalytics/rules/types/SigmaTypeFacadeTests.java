/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

public class SigmaTypeFacadeTests extends OpenSearchTestCase {

    public void testConversionStr() {
        SigmaType sigmaType = SigmaTypeFacade.sigmaType("Test");
        Assert.assertTrue(sigmaType instanceof SigmaString);
        Assert.assertEquals("Test", sigmaType.toString());
    }

    public void testConversionInt() {
        SigmaType sigmaType = SigmaTypeFacade.sigmaType(123);
        Assert.assertTrue(sigmaType instanceof SigmaNumber);
        Assert.assertEquals("123", sigmaType.toString());
    }

    public void testConversionFloat() {
        SigmaType sigmaType = SigmaTypeFacade.sigmaType(12.34f);
        Assert.assertTrue(sigmaType instanceof SigmaNumber);
        Assert.assertEquals("12.34", sigmaType.toString());
    }

    public void testConversionLongAndDoubleDoesNotNarrow() {
        for (Object value : new Object[] { Long.MAX_VALUE, Long.MIN_VALUE, 2147483648L, 1.2345678901234567d }) {
            SigmaType sigmaType = SigmaTypeFacade.sigmaType(value);
            assertTrue(sigmaType instanceof SigmaNumber);
            assertEquals(value.toString(), sigmaType.toString());
            assertEquals(value instanceof Long ? "long" : "double", ((SigmaNumber) sigmaType).getMappingType());
        }
        assertEquals("integer", new SigmaNumber(123).getMappingType());
        assertEquals("float", new SigmaNumber(12.34f).getMappingType());
    }

    public void testConversionBool() {
        SigmaType sigmaType = SigmaTypeFacade.sigmaType(true);
        Assert.assertTrue(sigmaType instanceof SigmaBool);
        Assert.assertEquals("true", sigmaType.toString());
    }

    public void testConversionNull() {
        SigmaType sigmaType = SigmaTypeFacade.sigmaType(null);
        Assert.assertTrue(sigmaType instanceof SigmaNull);
    }
}