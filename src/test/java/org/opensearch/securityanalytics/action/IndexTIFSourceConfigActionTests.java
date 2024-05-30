/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigAction;
import org.opensearch.test.OpenSearchTestCase;

public class IndexTIFSourceConfigActionTests extends OpenSearchTestCase {
    public void testIndexTIFSourceConfigActionName() {
        Assert.assertNotNull(SAIndexTIFSourceConfigAction.INSTANCE.name());
        Assert.assertEquals(SAIndexTIFSourceConfigAction.INSTANCE.name(), SAIndexTIFSourceConfigAction.NAME);
    }
}