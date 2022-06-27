/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.utils;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

import java.util.NoSuchElementException;

public class EitherTests extends OpenSearchTestCase {

    public void testEither() {
        Integer left = 1;
        Float right = 5.0f;

        Either<Integer, Float> val = Either.left(1);
        Assert.assertTrue(val.isLeft());
        Assert.assertEquals(left, val.getLeft());

        assertThrows(NoSuchElementException.class, val::get);

        val = Either.right(right);
        Assert.assertTrue(val.isRight());
        Assert.assertEquals(right, val.get());
    }
}