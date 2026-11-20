/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Map;

/** Tests that a custom log type name may not put the detector indices inside a registered system index pattern. */
public class IndexCustomLogTypeRequestTests extends OpenSearchTestCase {

    public void testAnOrdinaryNameIsAccepted() {
        assertNull(request("network-firewall").validate());
    }

    public void testANameStartingWithThreatIntelIsRejected() {
        ActionRequestValidationException e = request("threat-intel-feeds").validate();
        assertNotNull(e);
        assertTrue(e.getMessage(), e.getMessage().contains("is reserved"));
    }

    private static IndexCustomLogTypeRequest request(String name) {
        CustomLogType logType = new CustomLogType(null, null, name, "description", "Other", "Custom", Map.of());
        return new IndexCustomLogTypeRequest(null, WriteRequest.RefreshPolicy.IMMEDIATE, RestRequest.Method.POST, logType);
    }
}
