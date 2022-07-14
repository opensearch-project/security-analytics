/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.Collections;
import java.util.List;

public class SigmaStartswithModifierTests extends SigmaModifierTests {

    public void testStartswithNoWildcards() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaStartswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("foobar")));
        assertTrue(values.get(0) instanceof SigmaString);
        assertEquals("foobar*", values.get(0).toString());
    }

    public void testStartswithTrailingWildcards() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaStartswithModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("foobar*")));
        assertTrue(values.get(0) instanceof SigmaString);
        assertEquals("foobar*", values.get(0).toString());
    }
}