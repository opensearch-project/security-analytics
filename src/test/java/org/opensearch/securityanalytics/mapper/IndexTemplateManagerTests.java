/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import java.io.IOException;
import java.util.Map;
import org.opensearch.cluster.metadata.ComponentTemplate;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.test.OpenSearchTestCase;

public class IndexTemplateManagerTests extends OpenSearchTestCase {

    private static final Map<String, Object> SRC_IP_ALIAS = Map.of("type", "alias", "path", "fw.src");
    private static final Map<String, Object> DST_IP_ALIAS = Map.of("type", "alias", "path", "fw.dst");
    private static final Map<String, Object> IP = Map.of("type", "ip");

    private static ComponentTemplate componentTemplate(String mappingsJson) throws IOException {
        return new ComponentTemplate(new Template(null, new CompressedXContent(mappingsJson), null), 0L, null);
    }

    public void testMergeRetainsExistingProperties() throws IOException {
        ComponentTemplate existing = componentTemplate(
                "{\"_doc\":{\"properties\":{" +
                        "\"source.ip\":{\"type\":\"alias\",\"path\":\"fw.src\"}," +
                        "\"fw.src\":{\"type\":\"ip\"}" +
                        "}}}"
        );
        Map<String, Object> mappings = Map.of("properties", Map.of("destination.ip", DST_IP_ALIAS, "fw.dst", IP));

        Map<String, Object> merged = IndexTemplateManager.mergeWithExistingComponentTemplate(existing, mappings);

        assertEquals(
                Map.of("source.ip", SRC_IP_ALIAS, "fw.src", IP, "destination.ip", DST_IP_ALIAS, "fw.dst", IP),
                merged.get("properties")
        );
    }

    public void testMergeNewPropertiesWinOnConflict() throws IOException {
        ComponentTemplate existing = componentTemplate(
                "{\"properties\":{\"source.ip\":{\"type\":\"alias\",\"path\":\"fw.dst\"},\"fw.dst\":{\"type\":\"ip\"}}}"
        );
        Map<String, Object> mappings = Map.of("properties", Map.of("source.ip", SRC_IP_ALIAS, "fw.src", IP));

        Map<String, Object> merged = IndexTemplateManager.mergeWithExistingComponentTemplate(existing, mappings);

        assertEquals(Map.of("source.ip", SRC_IP_ALIAS, "fw.src", IP, "fw.dst", IP), merged.get("properties"));
    }

    public void testMergeWithEmptyNewPropertiesKeepsExisting() throws IOException {
        ComponentTemplate existing = componentTemplate(
                "{\"properties\":{\"source.ip\":{\"type\":\"alias\",\"path\":\"fw.src\"},\"fw.src\":{\"type\":\"ip\"}}}"
        );

        Map<String, Object> merged = IndexTemplateManager.mergeWithExistingComponentTemplate(existing, Map.of("properties", Map.of()));

        assertEquals(Map.of("source.ip", SRC_IP_ALIAS, "fw.src", IP), merged.get("properties"));
    }

    public void testMergeUnwrapsDocTypeInNewMappings() throws IOException {
        ComponentTemplate existing = componentTemplate(
                "{\"_doc\":{\"properties\":{\"source.ip\":{\"type\":\"alias\",\"path\":\"fw.src\"},\"fw.src\":{\"type\":\"ip\"}}}}"
        );
        Map<String, Object> mappings = Map.of("_doc", Map.of("properties", Map.of("destination.ip", DST_IP_ALIAS, "fw.dst", IP)));

        Map<String, Object> merged = IndexTemplateManager.mergeWithExistingComponentTemplate(existing, mappings);

        assertFalse(merged.containsKey("_doc"));
        assertEquals(
                Map.of("source.ip", SRC_IP_ALIAS, "fw.src", IP, "destination.ip", DST_IP_ALIAS, "fw.dst", IP),
                merged.get("properties")
        );
    }

    public void testMergeWithoutExistingMappingsReturnsNewMappings() {
        ComponentTemplate existing = new ComponentTemplate(new Template(null, null, null), 0L, null);
        Map<String, Object> mappings = Map.of("properties", Map.of("source.ip", SRC_IP_ALIAS));

        assertSame(mappings, IndexTemplateManager.mergeWithExistingComponentTemplate(existing, mappings));
        assertSame(mappings, IndexTemplateManager.mergeWithExistingComponentTemplate(null, mappings));
    }
}
