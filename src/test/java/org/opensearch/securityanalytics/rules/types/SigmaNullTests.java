/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

public class SigmaNullTests extends OpenSearchTestCase {

    public void testNullEqual() {
        SigmaNull n1 = new SigmaNull();
        SigmaNull n2 = new SigmaNull();
        Assert.assertEquals(n1, n2);
    }
}