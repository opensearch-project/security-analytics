/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.parser.modifiers.SigmaContainsModifier;
import org.opensearch.securityanalytics.rules.parser.types.SigmaString;
import org.opensearch.securityanalytics.rules.parser.types.SigmaType;
import org.opensearch.securityanalytics.rules.parser.utils.Either;

import java.util.Collections;
import java.util.List;

public class SigmaContainsModifierTests extends SigmaModifierTests {

    public void testContainsNoWildcards() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaContainsModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("foobar")));
        assertTrue(values.get(0) instanceof SigmaString);
        assertEquals("*foobar*", values.get(0).toString());
    }

    public void testContainsLeadingWildcards() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaContainsModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("*foobar")));
        assertTrue(values.get(0) instanceof SigmaString);
        assertEquals("*foobar*", values.get(0).toString());
    }

    public void testContainsTrailingWildcards() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaContainsModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("foobar*")));
        assertTrue(values.get(0) instanceof SigmaString);
        assertEquals("*foobar*", values.get(0).toString());
    }

    public void testContainsLeadingAndTrailingWildcards() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaContainsModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("*foobar*")));
        assertTrue(values.get(0) instanceof SigmaString);
        assertEquals("*foobar*", values.get(0).toString());
    }
}