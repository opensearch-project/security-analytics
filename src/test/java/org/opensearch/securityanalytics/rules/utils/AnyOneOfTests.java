/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.utils;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

import java.util.NoSuchElementException;

public class AnyOneOfTests extends OpenSearchTestCase {

    public void testAnyOneOf() {
        Integer left = 1;
        Float right = 5.0f;
        String middle = "Detects QuarksPwDump clearing access history in hive";

        AnyOneOf<Integer, String, Float> val = AnyOneOf.leftVal(1);
        Assert.assertTrue(val.isLeft());
        Assert.assertEquals(left, val.getLeft());

        assertThrows(NoSuchElementException.class, val::get);

        val = AnyOneOf.middleVal(middle);
        Assert.assertTrue(val.isMiddle());
        Assert.assertEquals(middle, val.getMiddle());

        val = AnyOneOf.rightVal(right);
        Assert.assertTrue(val.isRight());
        Assert.assertEquals(right, val.get());
    }
}