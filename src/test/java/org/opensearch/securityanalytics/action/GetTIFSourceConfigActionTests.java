/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.securityanalytics.threatIntel.action.SAGetTIFSourceConfigAction;
import org.opensearch.test.OpenSearchTestCase;

public class GetTIFSourceConfigActionTests extends OpenSearchTestCase {
    public void testGetTIFSourceConfigActionName() {
        Assert.assertNotNull(SAGetTIFSourceConfigAction.INSTANCE.name());
        Assert.assertEquals(SAGetTIFSourceConfigAction.INSTANCE.name(), SAGetTIFSourceConfigAction.NAME);
    }
}