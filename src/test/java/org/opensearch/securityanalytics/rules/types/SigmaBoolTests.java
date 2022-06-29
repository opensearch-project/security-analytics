/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

public class SigmaBoolTests extends OpenSearchTestCase {

    public void testBool() {
        SigmaBool b = new SigmaBool(true);
        Assert.assertTrue(b.isaBoolean());
    }

    public void testBoolToString() {
        SigmaBool b = new SigmaBool(true);
        Assert.assertEquals("true", b.toString());
    }
}