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
        SigmaRuleTag actualRuleTag = SigmaRuleTag.fromStr("tag");
        SigmaRuleTag expectedRuleTag = new SigmaRuleTag("", "tag");

        Assert.assertEquals(expectedRuleTag.getNamespace(), actualRuleTag.getNamespace());
        Assert.assertEquals(expectedRuleTag.getName(), actualRuleTag.getName());
        Assert.assertEquals("tag", actualRuleTag.getFormattedTag());
    }

    public void testSigmaRuleTagFromStr3Dots() {
        SigmaRuleTag actualRuleTag = SigmaRuleTag.fromStr("namespace.subnamespace.tag");
        SigmaRuleTag expectedRuleTag = new SigmaRuleTag("namespace", "subnamespace.tag");

        Assert.assertEquals(expectedRuleTag.getNamespace(), actualRuleTag.getNamespace());
        Assert.assertEquals(expectedRuleTag.getName(), actualRuleTag.getName());
        Assert.assertEquals("namespace.subnamespace.tag", actualRuleTag.getFormattedTag());
    }

    public void testSigmaRuleTagGovernanceAndCompliance() {
        SigmaRuleTag nistTag = SigmaRuleTag.fromStr("grc.nist.800-53.sc-8");
        Assert.assertEquals("grc", nistTag.getNamespace());
        Assert.assertEquals("nist.800-53.sc-8", nistTag.getName());
        Assert.assertEquals("grc.nist.800-53.sc-8", nistTag.getFormattedTag());

        SigmaRuleTag assetTag = SigmaRuleTag.fromStr("asset.tier.0_billing_cluster");
        Assert.assertEquals("asset", assetTag.getNamespace());
        Assert.assertEquals("tier.0_billing_cluster", assetTag.getName());
        Assert.assertEquals("asset.tier.0_billing_cluster", assetTag.getFormattedTag());
    }
}
