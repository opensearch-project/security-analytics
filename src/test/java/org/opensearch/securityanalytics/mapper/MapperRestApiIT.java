/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import org.apache.http.HttpStatus;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.securityanalytics.SecurityAnalyticsClientUtils;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

public class MapperRestApiIT extends SecurityAnalyticsRestTestCase {


    public void testCreateMappingSuccess() throws IOException {

        String testIndexName = "my_index";

        createSampleIndex(testIndexName);

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{ \"index_name\":\"" + testIndexName + "\"," +
                "  \"rule_topic\":\"netflow\", " +
                "  \"partial\":true" +
                "}"
        );
        // request.addParameter("indexName", testIndexName);
        // request.addParameter("ruleTopic", "netflow");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Verify mappings
        GetMappingsResponse getMappingsResponse = SecurityAnalyticsClientUtils.executeGetMappingsRequest(testIndexName);
        MappingsTraverser mappingsTraverser = new MappingsTraverser(getMappingsResponse.getMappings().iterator().next().value);
        List<String> flatProperties = mappingsTraverser.extractFlatNonAliasFields();
        assertTrue(flatProperties.contains("source.ip"));
        assertTrue(flatProperties.contains("destination.ip"));
        assertTrue(flatProperties.contains("source.port"));
        assertTrue(flatProperties.contains("destination.port"));
        // Try searching by alias field
        String query = "{" +
                "  \"query\": {" +
                "    \"query_string\": {" +
                "      \"query\": \"source.port:4444\"" +
                "    }" +
                "  }" +
                "}";
        SearchResponse searchResponse = SecurityAnalyticsClientUtils.executeSearchRequest(testIndexName, query);
        assertEquals(1L, searchResponse.getHits().getTotalHits().value);
    }

    public void testCreateMappingWithAliasesSuccess() throws IOException {

        String testIndexName = "my_index";

        createSampleIndex(testIndexName);

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{\n" +
                "   \"index_name\": \"my_index\",\n" +
                "  \"rule_topic\":\"netflow\", " +
                "  \"partial\":true," +
                "   \"alias_mappings\": {\n" +
                "        \"properties\": {\n" +
                "           \"source.ip\": {\n" +
                "              \"type\": \"alias\",\n" +
                "              \"path\": \"netflow.source_ipv4_address\"\n" +
                "           },\n" +
                "           \"source.port\": {\n" +
                "              \"type\": \"alias\",\n" +
                "              \"path\": \"netflow.source_transport_port\"\n" +
                "           }\n" +
                "       }\n" +
                "   }\n" +
                "}"
        );
        // request.addParameter("indexName", testIndexName);
        // request.addParameter("ruleTopic", "netflow");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Verify mappings
        GetMappingsResponse getMappingsResponse = SecurityAnalyticsClientUtils.executeGetMappingsRequest(testIndexName);
        MappingsTraverser mappingsTraverser = new MappingsTraverser(getMappingsResponse.getMappings().iterator().next().value);
        List<String> flatProperties = mappingsTraverser.extractFlatNonAliasFields();
        assertTrue(flatProperties.contains("source.ip"));
        assertTrue(flatProperties.contains("source.port"));
        // Try searching by alias field
        String query = "{" +
                "  \"query\": {" +
                "    \"query_string\": {" +
                "      \"query\": \"source.port:4444\"" +
                "    }" +
                "  }" +
                "}";
        SearchResponse searchResponse = SecurityAnalyticsClientUtils.executeSearchRequest(testIndexName, query);
        assertEquals(1L, searchResponse.getHits().getTotalHits().value);
    }

    public void testUpdateAndGetMappingSuccess() throws IOException {

        String testIndexName = "my_index";

        createSampleIndex(testIndexName);

        // Execute UpdateMappingsAction to add alias mapping for index
        Request updateRequest = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        updateRequest.setJsonEntity(
                "{ \"index_name\":\"" + testIndexName + "\"," +
                        "  \"field\":\"netflow.source_transport_port\","+
                        "  \"alias\":\"source.port\" }"
        );
        // request.addParameter("indexName", testIndexName);
        // request.addParameter("ruleTopic", "netflow");
        Response response = client().performRequest(updateRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Execute GetIndexMappingsAction and verify mappings
        Request getRequest = new Request("GET", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        getRequest.addParameter("index_name", testIndexName);
        response = client().performRequest(getRequest);
        XContentParser parser = createParser(JsonXContent.jsonXContent, new String(response.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8));
        assertTrue(
                (((Map)((Map)((Map)((Map)((Map)parser.map()
                        .get(testIndexName))
                        .get("mappings"))
                        .get("properties"))
                        .get("source"))
                        .get("properties"))
                        .containsKey("port"))
        );
        // Try searching by alias field
        String query = "{" +
                "  \"query\": {" +
                "    \"query_string\": {" +
                "      \"query\": \"source.port:4444\"" +
                "    }" +
                "  }" +
                "}";
        SearchResponse searchResponse = SecurityAnalyticsClientUtils.executeSearchRequest(testIndexName, query);
        assertEquals(1L, searchResponse.getHits().getTotalHits().value);
    }

    public void testExistingMappingsAreUntouched() throws IOException {
        String testIndexName = "existing_mappings_ok";

        createSampleIndex(testIndexName);

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{ \"index_name\":\"" + testIndexName + "\"," +
                        "  \"rule_topic\":\"netflow\"," +
                        "  \"partial\":true }"
        );
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Verify mappings
        GetMappingsResponse getMappingsResponse = SecurityAnalyticsClientUtils.executeGetMappingsRequest(testIndexName);
        Map<String, Object> properties =
                (Map<String, Object>) getMappingsResponse.getMappings().get(testIndexName)
                .getSourceAsMap().get("properties");
        // Verify that there is still mapping for integer field "plain1"
        assertTrue(((Map<String, Object>)properties.get("plain1")).get("type").equals("integer"));
    }

    public void testCreateIndexMappingsIndexMappingsEmpty() throws IOException {

        String testIndexName = "my_index_alias_fail_1";

        createIndex(testIndexName, Settings.EMPTY);

        // Execute UpdateMappingsAction to add alias mapping for index
        Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{ \"index_name\":\"" + testIndexName + "\"," +
                        "  \"rule_topic\":\"netflow\"," +
                        "  \"partial\":true }"
        );
        try {
            client().performRequest(request);
        } catch (ResponseException e) {
            assertTrue(e.getMessage().contains("Index mappings are empty"));
        }
    }

    public void testIndexNotExists() {

        String indexName = java.util.UUID.randomUUID().toString();

        Request request = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        request.addParameter("index_name", indexName);
        request.addParameter("field", "field1");
        request.addParameter("alias", "alias123");
        try {
            client().performRequest(request);
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Could not find index [" + indexName + "]"));
        }
    }

    public void testGetMappingsViewSuccess() throws IOException {

        String testIndexName = "get_mappings_view_index";

        createSampleIndex(testIndexName);

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", testIndexName);
        request.addParameter("rule_topic", "netflow");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = responseAsMap(response);
        // Verify alias mappings
        Map<String, Object> props = (Map<String, Object>) respMap.get("properties");
        assertEquals(4, props.size());
        assertTrue(props.containsKey("source.ip"));
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("source.port"));
        assertTrue(props.containsKey("destination.port"));
        // Verify unmapped index fields
        List<String> unmappedIndexFields = (List<String>) respMap.get("unmapped_index_fields");
        assertEquals(6, unmappedIndexFields.size());
        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(2, unmappedFieldAliases.size());
    }

    private void createSampleIndex(String indexName) throws IOException {
        String indexMapping =
                "    \"properties\": {" +
                        "        \"netflow.source_ipv4_address\": {" +
                        "          \"type\": \"ip\"" +
                        "        }," +
                        "        \"netflow.destination_transport_port\": {" +
                        "          \"type\": \"integer\"" +
                        "        }," +
                        "        \"netflow.destination_ipv4_address\": {" +
                        "          \"type\": \"ip\"" +
                        "        }," +
                        "        \"netflow.source_transport_port\": {" +
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
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.destination_transport_port\":1234," +
                "  \"netflow.destination_ipv4_address\":\"10.53.111.14\"," +
                "  \"netflow.source_transport_port\":4444" +
                "}";

        // Index doc
        Request indexRequest = new Request("POST", indexName + "/_doc?refresh=wait_for");
        indexRequest.setJsonEntity(sampleDoc);
        Response response = client().performRequest(indexRequest);
        assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
        // Refresh everything
        response = client().performRequest(new Request("POST", "_refresh"));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

}
