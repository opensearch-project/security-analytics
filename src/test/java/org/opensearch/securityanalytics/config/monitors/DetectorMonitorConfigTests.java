/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.config.monitors;

import org.opensearch.test.OpenSearchTestCase;

import java.util.Map;

public class DetectorMonitorConfigTests extends OpenSearchTestCase {

    public void testWildcardFieldsPreserveNativeQueryIndexMapping() {
        Map<String, Map<String, String>> mappings = DetectorMonitorConfig.getRuleIndexMappingsByType();

        assertFalse(mappings.containsKey("wildcard"));
        assertEquals(Map.of("analyzer", "rule_analyzer"), mappings.get("text"));
        assertFalse(mappings.containsKey("keyword"));
    }
}