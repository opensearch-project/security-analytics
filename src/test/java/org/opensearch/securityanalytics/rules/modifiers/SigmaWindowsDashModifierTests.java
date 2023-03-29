/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.parser.modifiers.SigmaWindowsDashModifier;
import org.opensearch.securityanalytics.rules.parser.types.SigmaExpansion;
import org.opensearch.securityanalytics.rules.parser.types.SigmaString;
import org.opensearch.securityanalytics.rules.parser.types.SigmaType;
import org.opensearch.securityanalytics.rules.parser.utils.Either;

import java.util.Collections;

public class SigmaWindowsDashModifierTests extends SigmaModifierTests {

    public void testWindash() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaType values = new SigmaWindowsDashModifier(dummyDetectionItem(), Collections.emptyList()).modify(Either.left(new SigmaString("-param-1 -param2"))).getLeft();
        assertTrue(values instanceof SigmaExpansion);
        assertTrue(((SigmaExpansion) values).getValues().get(0).toString().equals("-param-1_ws_-param2") ||
                ((SigmaExpansion) values).getValues().get(0).toString().equals("-param-1_ws_/param2") ||
                ((SigmaExpansion) values).getValues().get(0).toString().equals("/param-1_ws_-param2") ||
                ((SigmaExpansion) values).getValues().get(0).toString().equals("/param-1_ws_/param2"));
        assertTrue(((SigmaExpansion) values).getValues().get(1).toString().equals("-param-1_ws_-param2") ||
                ((SigmaExpansion) values).getValues().get(1).toString().equals("-param-1_ws_/param2") ||
                ((SigmaExpansion) values).getValues().get(1).toString().equals("/param-1_ws_-param2") ||
                ((SigmaExpansion) values).getValues().get(1).toString().equals("/param-1_ws_/param2"));
        assertTrue(((SigmaExpansion) values).getValues().get(2).toString().equals("-param-1_ws_-param2") ||
                ((SigmaExpansion) values).getValues().get(2).toString().equals("-param-1_ws_/param2") ||
                ((SigmaExpansion) values).getValues().get(2).toString().equals("/param-1_ws_-param2") ||
                ((SigmaExpansion) values).getValues().get(2).toString().equals("/param-1_ws_/param2"));
        assertTrue(((SigmaExpansion) values).getValues().get(3).toString().equals("-param-1_ws_-param2") ||
                ((SigmaExpansion) values).getValues().get(3).toString().equals("-param-1_ws_/param2") ||
                ((SigmaExpansion) values).getValues().get(3).toString().equals("/param-1_ws_-param2") ||
                ((SigmaExpansion) values).getValues().get(3).toString().equals("/param-1_ws_/param2"));
    }
}