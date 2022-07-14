/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.Collections;
import java.util.List;

public class SigmaRegularExpressionModifierTests extends SigmaModifierTests {

    public void testRe() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaRegularExpressionModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("foo?bar.*")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals("foo?bar.*", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testDoNotEscapeRe() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaRegularExpressionModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("foo\\bar")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals("foo\\bar", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReContains() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaContainsModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("foo?bar")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals(".*foo?bar.*", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReContainsStart() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaContainsModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("^foo?bar")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals("^foo?bar.*", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReContainsEnd() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaContainsModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("foo?bar$")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals(".*foo?bar$", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReContainsStartswithWildcard() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaContainsModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression(".*foo?bar")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals(".*foo?bar.*", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReContainsEndswithWildcard() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaContainsModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("foo?bar.*")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals(".*foo?bar.*", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReStartswith() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaStartswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("foo?bar")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals("foo?bar.*", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReEndswith() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaEndswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("foo?bar")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals(".*foo?bar", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReStartswithStart() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaStartswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("^foo?bar")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals("^foo?bar.*", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReEndswithStart() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaEndswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("^foo?bar")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals("^foo?bar", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReStartswithEnd() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaStartswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("foo?bar$")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals("foo?bar$", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReEndswithEnd() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaEndswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("foo?bar$")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals(".*foo?bar$", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReEndswithStartswithWildcard() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaEndswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression(".*foo?bar")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals(".*foo?bar", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReStartswithEndswithWildcard() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaStartswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("foo?bar.*")));
        Assert.assertTrue(values.get(0) instanceof SigmaRegularExpression);
        Assert.assertEquals("foo?bar.*", ((SigmaRegularExpression) values.get(0)).getRegexp());
    }

    public void testReWithOther() {
        Exception exception = assertThrows(SigmaValueError.class, () -> {
            new SigmaRegularExpressionModifier(dummyDetectionItem(), List.of(SigmaBase64Modifier.class)).apply(Either.left(new SigmaString("foo?bar.*")));
        });

        String expectedMessage = "Regular expression modifier only applicable to unmodified values";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }
}