/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import com.carrotsearch.randomizedtesting.generators.RandomStrings;
import org.apache.http.HttpStatus;
import org.junit.Test;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.common.ParseField;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.securityanalytics.ClientUtils;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class MapperIT extends OpenSearchRestTestCase {

    static final ParseField MAPPINGS = new ParseField("mappings");

    public void testCreateMappingSuccess() throws IOException {

        String testIndexName = "my_index";

        createSampleIndex(testIndexName);

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{ \"indexName\":\"" + testIndexName + "\"," +
                "  \"ruleTopic\":\"netflow\" }"
        );
        // request.addParameter("indexName", testIndexName);
        // request.addParameter("ruleTopic", "netflow");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

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

    public void testUpdateAndGetMappingSuccess() throws IOException {

        String testIndexName = "my_index";

        createSampleIndex(testIndexName);

        // Execute UpdateMappingsAction to add alias mapping for index
        Request updateRequest = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        updateRequest.setJsonEntity(
                "{ \"indexName\":\"" + testIndexName + "\"," +
                        "  \"field\":\"netflow.event_data.SourcePort\","+
                        "  \"alias\":\"srcport\" }"
        );
        // request.addParameter("indexName", testIndexName);
        // request.addParameter("ruleTopic", "netflow");
        Response response = client().performRequest(updateRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Execute GetIndexMappingsAction and verify mappings
        Request getRequest = new Request("GET", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        getRequest.addParameter("indexName", testIndexName);
        response = client().performRequest(getRequest);
        XContentParser parser = createParser(JsonXContent.jsonXContent, new String(response.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8));
        assertTrue(
                ((HashMap<Object, Object>)((HashMap<Object, Object>)((HashMap<Object, Object>)parser.map()
                        .get(testIndexName))
                        .get("mappings"))
                        .get("properties"))
                        .containsKey("srcport")
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

    public void testExistingMappingsAreUntouched() throws IOException {
        String testIndexName = "existing_mappings_ok";

        createSampleIndex(testIndexName);

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{ \"indexName\":\"" + testIndexName + "\"," +
                        "  \"ruleTopic\":\"netflow\" }"
        );
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Verify mappings
        GetMappingsResponse getMappingsResponse = ClientUtils.executeGetMappingsRequest(testIndexName);
        Map<String, Object> properties =
                (Map<String, Object>) getMappingsResponse.getMappings().get(testIndexName)
                .getSourceAsMap().get("properties");
        // Verify that there is still mapping for integer field "plain1"
        assertTrue(((Map<String, Object>)properties.get("plain1")).get("type").equals("integer"));
    }

    public void testMappingMissingForAliasPath() throws IOException {

        String testIndexName = "my_index_alias_fail_1";

        createIndex(testIndexName, Settings.EMPTY);

        // Execute UpdateMappingsAction to add alias mapping for index
        Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{ \"indexName\":\"" + testIndexName + "\"," +
                        "  \"ruleTopic\":\"netflow\" }"
        );
        try {
            client().performRequest(request);
        } catch (ResponseException e) {
            assertTrue(
                    e.getMessage().contains("Not all paths were found in index mappings:" +
                            " [netflow.event_data.SourceAddress, netflow.event_data.DestinationPort, " +
                            "netflow.event_data.SourcePort, netflow.event_data.DestAddress, user.first]")
                    );
        }
    }

    public void testIndexNotExists() {

        String indexName = java.util.UUID.randomUUID().toString();

        Request request = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        request.addParameter("indexName", indexName);
        request.addParameter("field", "field1");
        request.addParameter("alias", "alias123");
        try {
            client().performRequest(request);
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Could not find index [" + indexName + "]"));
        }
    }

    private void createSampleIndex(String indexName) throws IOException {
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
                        "        }," +
                        "        \"netflow.event.stop\": {" +
                        "          \"type\": \"integer\"" +
                        "        }," +
                        "        \"dns.event.stop\": {" +
                        "          \"type\": \"integer\"" +
                        "        }," +
                        "        \"ipx.event.stop\": {" +
                        "          \"type\": \"integer\"" +
                        "        }," +
                        "        \"plain1\": {" +
                        "          \"type\": \"integer\"" +
                        "        }," +
                        "        \"user\":{" +
                        "          \"type\":\"nested\"," +
                        "            \"properties\":{" +
                        "              \"first\":{" +
                        "                \"type\":\"text\"," +
                        "                  \"fields\":{" +
                        "                    \"keyword\":{" +
                        "                      \"type\":\"keyword\"," +
                        "                      \"ignore_above\":256" +
                                              "}" +
                                            "}" +
                                        "}," +
                        "              \"last\":{" +
                                          "\"type\":\"text\"," +
                                            "\"fields\":{" +
                        "                      \"keyword\":{" +
                        "                           \"type\":\"keyword\"," +
                        "                           \"ignore_above\":256" +
                                                "}" +
                                            "}" +
                                        "}" +
                                    "}" +
                                "}" +
                        "    }";

        createIndex(indexName, Settings.EMPTY, indexMapping);

        // Insert sample doc
        String sampleDoc = "{" +
                "  \"netflow.event_data.SourceAddress\":\"10.50.221.10\"," +
                "  \"netflow.event_data.DestinationPort\":1234," +
                "  \"netflow.event_data.DestAddress\":\"10.53.111.14\"," +
                "  \"netflow.event_data.SourcePort\":4444" +
                "}";

        Request indexRequest = new Request("POST", indexName + "/_doc?refresh=wait_for");
        indexRequest.setJsonEntity(sampleDoc);
        Response response = client().performRequest(indexRequest);
        assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
    }

}
