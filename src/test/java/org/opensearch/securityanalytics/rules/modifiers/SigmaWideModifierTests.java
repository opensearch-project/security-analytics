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

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

public class SigmaWideModifierTests extends SigmaModifierTests {

    public void testWide() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaWideModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("*foobar*")));
        assertTrue(values.get(0) instanceof SigmaString);
        byte[] expected = new byte[]{102, 0, 111, 0, 111, 0, 98, 0, 97, 0, 114, 0};
        assertArrayEquals(expected, ((SigmaString) values.get(0)).getsOpt().get(1).getLeft().getBytes(StandardCharsets.UTF_8));
    }
}