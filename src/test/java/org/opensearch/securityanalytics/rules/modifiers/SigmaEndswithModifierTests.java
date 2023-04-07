/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.parser.modifiers.SigmaEndswithModifier;
import org.opensearch.securityanalytics.rules.parser.types.SigmaString;
import org.opensearch.securityanalytics.rules.parser.types.SigmaType;
import org.opensearch.securityanalytics.rules.parser.utils.Either;

import java.util.Collections;
import java.util.List;

public class SigmaEndswithModifierTests extends SigmaModifierTests {

    public void testEndswithNoWildcards() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaEndswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("foobar")));
        assertTrue(values.get(0) instanceof SigmaString);
        assertEquals("*foobar", values.get(0).toString());
    }

    public void testEndswithLeadingWildcards() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaEndswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("*foobar")));
        assertTrue(values.get(0) instanceof SigmaString);
        assertEquals("*foobar", values.get(0).toString());
    }
}