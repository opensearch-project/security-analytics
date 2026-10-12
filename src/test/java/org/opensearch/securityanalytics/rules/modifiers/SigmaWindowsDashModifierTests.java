/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.types.SigmaExpansion;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.Collections;

public class SigmaWindowsDashModifierTests extends SigmaModifierTests {

    public void testWindash() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        SigmaType values = new SigmaWindowsDashModifier(dummyDetectionItem(), Collections.emptyList()).modify(Either.left(new SigmaString("-param-1 -param2"))).getLeft();
        assertTrue(values instanceof SigmaExpansion);
        // After Phase 1 whitespace fix: toString() returns literal spaces (not _ws_).
        // The windash modifier no longer re-encodes spaces as _ws_; backslash-escape happens at
        // backend emit time. Each variant must contain a literal space, not _ws_.
        for (int i = 0; i < 4; i++) {
            String v = ((SigmaExpansion) values).getValues().get(i).toString();
            assertFalse("Windash value must not contain _ws_ token: " + v, v.contains("_ws_"));
            assertTrue("Windash value must contain a literal space: " + v,
                    v.equals("-param-1 -param2") ||
                    v.equals("-param-1 /param2") ||
                    v.equals("/param-1 -param2") ||
                    v.equals("/param-1 /param2"));
        }
    }
}
