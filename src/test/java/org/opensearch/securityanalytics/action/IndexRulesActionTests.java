/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

public class IndexRulesActionTests extends OpenSearchTestCase {

    public void testIndexRulesActionName() {
        Assert.assertNotNull(IndexRulesAction.INSTANCE.name());
        Assert.assertEquals(IndexRulesAction.INSTANCE.name(), IndexRulesAction.NAME);
    }
}