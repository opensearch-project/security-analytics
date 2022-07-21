/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mappings;

import org.junit.Assert;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsRequest;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.io.IOException;
import java.util.Map;

public class MapperApplierIT extends OpenSearchIntegTestCase {

    @SuppressWarnings("unchecked")
    public void testCreateMappingActionForNetwork() throws IOException {
        CreateIndexRequest indexRequest = new CreateIndexRequest("network")
                .mapping("{\n" +
                        "    \"properties\": {\n" +
                        "      \"src_ip\": {\n" +
                        "        \"type\": \"integer\"\n" +
                        "      },\n" +
                        "      \"field2\": {\n" +
                        "        \"type\": \"float\"\n" +
                        "      }\n" +
                        "    }\n" +
                        "  }", XContentType.JSON)
                .settings(Settings.EMPTY);
        client().admin().indices().create(indexRequest).actionGet();

        MapperApplier mapperApplier = new MapperApplier();
        PutMappingRequest mappingRequest = mapperApplier.createMappingAction("network", "network");
        client().admin().indices().putMapping(mappingRequest).actionGet();

        GetMappingsRequest getMappingsRequest = new GetMappingsRequest().indices("network");
        GetMappingsResponse response = client().admin().indices().getMappings(getMappingsRequest).actionGet();
        Assert.assertTrue(((Map<String, Object>) response.getMappings().get("network").getSourceAsMap().get("properties")).containsKey("source"));
    }
}