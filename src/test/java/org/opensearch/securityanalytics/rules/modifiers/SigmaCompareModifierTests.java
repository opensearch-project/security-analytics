/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.*;
import org.opensearch.securityanalytics.rules.types.SigmaCompareExpression;
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.Collections;
import java.util.List;

public class SigmaCompareModifierTests extends SigmaModifierTests {

    public void testLt() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaLessThanModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaNumber(123)));
        Assert.assertTrue(values.get(0) instanceof SigmaCompareExpression);
        Assert.assertEquals("123", ((SigmaCompareExpression) values.get(0)).getNumber().toString());
        Assert.assertEquals(SigmaCompareExpression.CompareOperators.LT, ((SigmaCompareExpression) values.get(0)).getOp());
    }

    public void testLte() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaLessThanEqualModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaNumber(123)));
        Assert.assertTrue(values.get(0) instanceof SigmaCompareExpression);
        Assert.assertEquals("123", ((SigmaCompareExpression) values.get(0)).getNumber().toString());
        Assert.assertEquals(SigmaCompareExpression.CompareOperators.LTE, ((SigmaCompareExpression) values.get(0)).getOp());
    }

    public void testGt() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaGreaterThanModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaNumber(123)));
        Assert.assertTrue(values.get(0) instanceof SigmaCompareExpression);
        Assert.assertEquals("123", ((SigmaCompareExpression) values.get(0)).getNumber().toString());
        Assert.assertEquals(SigmaCompareExpression.CompareOperators.GT, ((SigmaCompareExpression) values.get(0)).getOp());
    }

    public void testGte() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaGreaterThanEqualModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaNumber(123)));
        Assert.assertTrue(values.get(0) instanceof SigmaCompareExpression);
        Assert.assertEquals("123", ((SigmaCompareExpression) values.get(0)).getNumber().toString());
        Assert.assertEquals(SigmaCompareExpression.CompareOperators.GTE, ((SigmaCompareExpression) values.get(0)).getOp());
    }

    public void testCompareString() {
        assertThrows(SigmaTypeError.class, () -> {
            new SigmaGreaterThanEqualModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("123")));
        });
    }
}