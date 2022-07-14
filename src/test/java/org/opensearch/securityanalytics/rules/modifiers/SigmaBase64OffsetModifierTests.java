/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.types.SigmaExpansion;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.Collections;
import java.util.List;

public class SigmaBase64OffsetModifierTests extends SigmaModifierTests {

    public void testBase64Offset() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaBase64OffsetModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("foobar")));
        assertTrue(values.get(0) instanceof SigmaExpansion);
        assertEquals("Zm9vYmFy", ((SigmaExpansion) values.get(0)).getValues().get(0).toString());
        assertEquals("Zvb2Jhc", ((SigmaExpansion) values.get(0)).getValues().get(1).toString());
        assertEquals("mb29iYX", ((SigmaExpansion) values.get(0)).getValues().get(2).toString());
    }

    public void testBase64Wildcards() {
        Exception exception = assertThrows(SigmaValueError.class, () -> {
            new SigmaBase64OffsetModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("foo*bar")));
        });

        String expectedMessage = "Base64 encoding of strings with wildcards is not allowed";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testBase64Re() {
        assertThrows(SigmaTypeError.class, () -> {
            new SigmaBase64OffsetModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaRegularExpression("foo.*bar")));
        });
    }
}