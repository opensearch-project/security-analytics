/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.modifiers.SigmaAllModifier;
import org.opensearch.securityanalytics.rules.modifiers.SigmaContainsModifier;
import org.opensearch.securityanalytics.rules.types.SigmaNull;
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collections;
import java.util.List;

public class SigmaDetectionItemTests extends OpenSearchTestCase {

    public void testSigmaDetectionItemKeywordSingle() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromMapping(null, Either.left("value"));

        SigmaDetectionItem expectedDetectionItem = new SigmaDetectionItem(null, Collections.emptyList(), List.of(new SigmaString("value")), null, null, false);
        Assert.assertTrue(actualDetectionItem.getValue().get(0) instanceof SigmaString);
        Assert.assertEquals(((SigmaString) expectedDetectionItem.getValue().get(0)).getOriginal(), ((SigmaString) actualDetectionItem.getValue().get(0)).getOriginal());
    }

    public void testSigmaDetectionItemIsKeyword() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromMapping(null, Either.left("value"));
        Assert.assertTrue(actualDetectionItem.isKeyword());
    }

    public void testSigmaDetectionItemIsNotKeyword() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromMapping("field", Either.left("value"));
        Assert.assertFalse(actualDetectionItem.isKeyword());
    }

    public void testSigmaDetectionItemKeywordList() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromMapping(null,
                Either.right(List.of("value", 123)));

        SigmaDetectionItem expectedDetectionItem = new SigmaDetectionItem(null, Collections.emptyList(),
                List.of(new SigmaString("value"), new SigmaNumber(123)), null, null, false);

        Assert.assertTrue(actualDetectionItem.getValue().get(0) instanceof SigmaString);
        Assert.assertTrue(actualDetectionItem.getValue().get(1) instanceof SigmaNumber);
        Assert.assertEquals(((SigmaString) expectedDetectionItem.getValue().get(0)).getOriginal(), ((SigmaString) actualDetectionItem.getValue().get(0)).getOriginal());
        Assert.assertEquals(expectedDetectionItem.getValue().get(1).toString(), actualDetectionItem.getValue().get(1).toString());
    }

    public void testSigmaDetectionItemKeywordModifiers() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromMapping("|contains", Either.left("value"));

        SigmaDetectionItem expectedDetectionItem = new SigmaDetectionItem(null, List.of(SigmaContainsModifier.class), List.of(new SigmaString("value")), null, null, false);

        Assert.assertTrue(actualDetectionItem.getValue().get(0) instanceof SigmaString);
        Assert.assertEquals(expectedDetectionItem.getModifiers().get(0), actualDetectionItem.getModifiers().get(0));
    }

    public void testSigmaDetectionItemUnknownModifier() {
        Exception exception = assertThrows(SigmaModifierError.class, () -> {
            SigmaDetectionItem.fromMapping("key|foobar", Either.left("value"));
        });

        String expectedMessage = "Unknown modifier foobar";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testSigmaDetectionKeyValueSingleString() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromMapping("key", Either.left("value"));

        SigmaDetectionItem expectedDetectionItem = new SigmaDetectionItem("key", Collections.emptyList(), List.of(new SigmaString("value")), null, null, false);
        Assert.assertEquals(expectedDetectionItem.getField(), actualDetectionItem.getField());
        Assert.assertTrue(actualDetectionItem.getValue().get(0) instanceof SigmaString);
        Assert.assertEquals(((SigmaString) expectedDetectionItem.getValue().get(0)).getOriginal(), ((SigmaString) actualDetectionItem.getValue().get(0)).getOriginal());
    }

    public void testSigmaDetectionKeyValueSingleInt() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromMapping("key", Either.left(123));

        SigmaDetectionItem expectedDetectionItem = new SigmaDetectionItem("key", Collections.emptyList(), List.of(new SigmaNumber(123)), null, null, false);
        Assert.assertEquals(expectedDetectionItem.getField(), actualDetectionItem.getField());
        Assert.assertTrue(actualDetectionItem.getValue().get(0) instanceof SigmaNumber);
        Assert.assertEquals(expectedDetectionItem.getValue().get(0).toString(), actualDetectionItem.getValue().get(0).toString());
    }

    public void testSigmaDetectionKeyValueSingleFloat() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromMapping("key", Either.left(12.34f));

        SigmaDetectionItem expectedDetectionItem = new SigmaDetectionItem("key", Collections.emptyList(), List.of(new SigmaNumber(12.34f)), null, null, false);
        Assert.assertEquals(expectedDetectionItem.getField(), actualDetectionItem.getField());
        Assert.assertTrue(actualDetectionItem.getValue().get(0) instanceof SigmaNumber);
        Assert.assertEquals(expectedDetectionItem.getValue().get(0).toString(), actualDetectionItem.getValue().get(0).toString());
    }

    public void testSigmaDetectionKeyValueNull() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromMapping("key", null);

        SigmaDetectionItem expectedDetectionItem = new SigmaDetectionItem("key", Collections.emptyList(), List.of(new SigmaNull()), null, null, false);
        Assert.assertEquals(expectedDetectionItem.getField(), actualDetectionItem.getField());
        Assert.assertTrue(actualDetectionItem.getValue().get(0) instanceof SigmaNull);
    }

    public void testSigmaDetectionItemKeyValueList() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromMapping("field",
                Either.right(List.of("value", 123)));

        SigmaDetectionItem expectedDetectionItem = new SigmaDetectionItem("field", Collections.emptyList(),
                List.of(new SigmaString("value"), new SigmaNumber(123)), null, null, false);

        Assert.assertEquals(expectedDetectionItem.getField(), actualDetectionItem.getField());
        Assert.assertTrue(actualDetectionItem.getValue().get(0) instanceof SigmaString);
        Assert.assertTrue(actualDetectionItem.getValue().get(1) instanceof SigmaNumber);
        Assert.assertEquals(((SigmaString) expectedDetectionItem.getValue().get(0)).getOriginal(), ((SigmaString) actualDetectionItem.getValue().get(0)).getOriginal());
        Assert.assertEquals(expectedDetectionItem.getValue().get(1).toString(), actualDetectionItem.getValue().get(1).toString());
    }

    public void testSigmaDetectionItemKeyValueModifiers() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromMapping("key|contains|all", Either.left("value"));

        SigmaDetectionItem expectedDetectionItem = new SigmaDetectionItem("key", List.of(SigmaContainsModifier.class, SigmaAllModifier.class),
                List.of(new SigmaString("value")), null, null, false);

        Assert.assertEquals(expectedDetectionItem.getField(), actualDetectionItem.getField());
        Assert.assertTrue(actualDetectionItem.getValue().get(0) instanceof SigmaString);
        Assert.assertEquals(expectedDetectionItem.getModifiers().get(0), actualDetectionItem.getModifiers().get(0));
        Assert.assertEquals(expectedDetectionItem.getModifiers().get(1), actualDetectionItem.getModifiers().get(1));
    }

    public void testSigmaDetectionItemFromValue() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaDetectionItem actualDetectionItem = SigmaDetectionItem.fromValue(Either.left("test"));
        SigmaDetectionItem expectedDetectionItem = new SigmaDetectionItem(null, Collections.emptyList(), List.of(new SigmaString("test")), null, null, false);
        Assert.assertTrue(actualDetectionItem.getValue().get(0) instanceof SigmaString);
        Assert.assertEquals(((SigmaString) expectedDetectionItem.getValue().get(0)).getOriginal(), ((SigmaString) actualDetectionItem.getValue().get(0)).getOriginal());
    }
}