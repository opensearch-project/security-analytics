/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.parser.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.parser.modifiers.SigmaBase64Modifier;
import org.opensearch.securityanalytics.rules.parser.modifiers.SigmaCIDRModifier;
import org.opensearch.securityanalytics.rules.parser.types.SigmaCIDRExpression;
import org.opensearch.securityanalytics.rules.parser.types.SigmaString;
import org.opensearch.securityanalytics.rules.parser.types.SigmaType;
import org.opensearch.securityanalytics.rules.parser.utils.Either;

import java.util.Collections;
import java.util.List;

public class SigmaCIDRModifierTests extends SigmaModifierTests {

    public void testCidr() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.0/24")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("192.168.1.0/24", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrWithOther() {
        Exception exception = assertThrows(SigmaValueError.class, () -> {
            new SigmaCIDRModifier(dummyDetectionItem(), List.of(SigmaBase64Modifier.class)).apply(Either.left(new SigmaString("192.168.1.0/24")));
        });

        String expectedMessage = "CIDR expression modifier only applicable to unmodified values";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }
}