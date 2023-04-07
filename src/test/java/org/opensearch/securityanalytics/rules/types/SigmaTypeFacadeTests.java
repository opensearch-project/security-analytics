/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.parser.types.SigmaBool;
import org.opensearch.securityanalytics.rules.parser.types.SigmaNull;
import org.opensearch.securityanalytics.rules.parser.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.parser.types.SigmaString;
import org.opensearch.securityanalytics.rules.parser.types.SigmaType;
import org.opensearch.securityanalytics.rules.parser.types.SigmaTypeFacade;
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