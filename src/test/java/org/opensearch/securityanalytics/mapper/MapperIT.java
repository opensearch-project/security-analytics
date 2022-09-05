/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import org.apache.http.HttpStatus;
import org.junit.Test;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.common.ParseField;
import org.opensearch.common.bytes.BytesArray;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.securityanalytics.ClientUtils;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class MapperIT extends OpenSearchRestTestCase {

    static final ParseField MAPPINGS = new ParseField("mappings");

    @Test
    public void testMappingSuccess() throws IOException {

        String testIndexName = "my_index";

        String indexMapping =
                "    \"properties\": {" +
                "        \"netflow.event_data.SourceAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.DestinationPort\": {" +
                "          \"type\": \"integer\"" +
                "        }," +
                "        \"netflow.event_data.DestAddress\": {" +
                "          \"type\": \"ip\"" +
                "        }," +
                "        \"netflow.event_data.SourcePort\": {" +
                "          \"type\": \"integer\"" +
                "        }" +
                "    }";

        createIndex(testIndexName, Settings.EMPTY, indexMapping);

        // Insert sample doc
        String sampleDoc = "{" +
                "  \"netflow.event_data.SourceAddress\":\"10.50.221.10\"," +
                "  \"netflow.event_data.DestinationPort\":1234," +
                "  \"netflow.event_data.DestAddress\":\"10.53.111.14\"," +
                "  \"netflow.event_data.SourcePort\":4444" +
                "}";

        Request indexRequest = new Request("POST", testIndexName + "/_doc?refresh=wait_for");
        indexRequest.setJsonEntity(sampleDoc);
        Response response = client().performRequest(indexRequest);
        assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());

        // Execute UpdateMappingsAction to add alias mapping for index
        Request request = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        request.addParameter("indexName", testIndexName);
        request.addParameter("ruleTopic", "netflow");

        response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        client().performRequest(new Request("POST", testIndexName + "/_refresh"));

        // Verify mappings
        GetMappingsResponse getMappingsResponse = ClientUtils.executeGetMappingsRequest(testIndexName);
        assertTrue(
                ((HashMap<Object, Object>)getMappingsResponse.getMappings().get(testIndexName)
                        .getSourceAsMap().get("properties"))
                        .containsKey("srcaddr")
        );
        assertTrue(
                ((HashMap<Object, Object>)getMappingsResponse.getMappings().get(testIndexName)
                        .getSourceAsMap().get("properties"))
                        .containsKey("dstaddr")
        );
        assertTrue(
                ((HashMap<Object, Object>)getMappingsResponse.getMappings().get(testIndexName)
                        .getSourceAsMap().get("properties"))
                        .containsKey("srcport")
        );
        assertTrue(
                ((HashMap<Object, Object>)getMappingsResponse.getMappings().get(testIndexName)
                        .getSourceAsMap().get("properties"))
                        .containsKey("dstport")
        );
        // Try searching by alias field
        String query = "{" +
                "  \"query\": {" +
                "    \"query_string\": {" +
                "      \"query\": \"srcport:4444\"" +
                "    }" +
                "  }" +
                "}";
        SearchResponse searchResponse = ClientUtils.executeSearchRequest(testIndexName, query);
        assertEquals(1L, searchResponse.getHits().getTotalHits().value);
    }

    @Test
    public void testIndexNotExists() throws IOException {

        Request request = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        request.addParameter("indexName", "myIndex");
        request.addParameter("ruleTopic", "netflow");
        try {
            client().performRequest(request);
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Could not find index [myIndex]"));
        }
    }

}
