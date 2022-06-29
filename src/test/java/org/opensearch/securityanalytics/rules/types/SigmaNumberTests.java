/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

public class SigmaNumberTests extends OpenSearchTestCase {

    public void testNumberInt() {
        SigmaNumber n = new SigmaNumber(123);
        Assert.assertEquals("123", n.toString());
    }

    public void testNumberFloat() {
        SigmaNumber n = new SigmaNumber(12.34f);
        Assert.assertEquals("12.34", n.toString());
    }

    public void testNumberEqual() {
        SigmaNumber n1 = new SigmaNumber(123);
        SigmaNumber n2 = new SigmaNumber(123);
        Assert.assertEquals(n1, n2);
    }
}