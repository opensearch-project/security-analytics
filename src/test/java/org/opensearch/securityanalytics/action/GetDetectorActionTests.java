/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

public class GetDetectorActionTests extends OpenSearchTestCase {

    public void testIndexDetectorActionName() {
        Assert.assertNotNull(GetDetectorAction.INSTANCE.name());
        Assert.assertEquals(GetDetectorAction.INSTANCE.name(), GetDetectorAction.NAME);
    }
}