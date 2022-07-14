/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

public class SigmaRuleTagTests extends OpenSearchTestCase {

    public void testSigmaRuleTagFromStr() {
        SigmaRuleTag actualRuleTag = SigmaRuleTag.fromStr("namespace.name");
        SigmaRuleTag expectedRuleTag = new SigmaRuleTag("namespace", "name");

        Assert.assertEquals(expectedRuleTag.getNamespace(), actualRuleTag.getNamespace());
        Assert.assertEquals(expectedRuleTag.getName(), actualRuleTag.getName());
    }

    public void testSigmaRuleTagFromStrNoDot() {
        Exception exception = assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            SigmaRuleTag.fromStr("tag");
        });

        String expectedMessage = "Index 1 out of bounds for length 1";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testSigmaRuleTagFromStr3Dots() {
        SigmaRuleTag actualRuleTag = SigmaRuleTag.fromStr("namespace.subnamespace.tag");
        SigmaRuleTag expectedRuleTag = new SigmaRuleTag("namespace", "subnamespace.tag");

        Assert.assertEquals(expectedRuleTag.getNamespace(), actualRuleTag.getNamespace());
        Assert.assertEquals(expectedRuleTag.getName(), actualRuleTag.getName());
    }
}