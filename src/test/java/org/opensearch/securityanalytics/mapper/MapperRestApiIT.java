/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import java.util.Collections;
import java.util.Optional;
import org.apache.http.HttpStatus;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.common.Strings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.DeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.securityanalytics.SecurityAnalyticsClientUtils;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Verify mappings
        GetMappingsResponse getMappingsResponse = SecurityAnalyticsClientUtils.executeGetMappingsRequest(testIndexName);
        MappingsTraverser mappingsTraverser = new MappingsTraverser(getMappingsResponse.getMappings().iterator().next().value);
        // After applying netflow aliases, our index will have 4 alias mappings
        List<String> flatProperties = mappingsTraverser.extractFlatNonAliasFields();
        assertFalse(flatProperties.contains("source.ip"));
        assertFalse(flatProperties.contains("destination.ip"));
        assertFalse(flatProperties.contains("source.port"));
        assertFalse(flatProperties.contains("destination.port"));
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
        assertFalse(flatProperties.contains("source.ip"));
        assertFalse(flatProperties.contains("source.port"));
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

    public void testUpdateAndGetMapping_notFound_Success() throws IOException {

        String testIndexName = "my_index";

        createSampleIndex(testIndexName);

        // Execute UpdateMappingsAction to add alias mapping for index
        Request updateRequest = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        updateRequest.setJsonEntity(
                "{ \"index_name\":\"" + testIndexName + "\"," +
                        "  \"field\":\"netflow.source_transport_port\","+
                        "  \"alias\":\"\\u0000\" }"
        );
        // request.addParameter("indexName", testIndexName);
        // request.addParameter("ruleTopic", "netflow");
        Response response = client().performRequest(updateRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Execute GetIndexMappingsAction and verify mappings
        Request getRequest = new Request("GET", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        getRequest.addParameter("index_name", testIndexName);
        try {
            client().performRequest(getRequest);
            fail();
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_NOT_FOUND, e.getResponse().getStatusLine().getStatusCode());
            assertTrue(e.getMessage().contains("No applied aliases not found"));
        }
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
            assertTrue(e.getMessage().contains("Mappings for index [my_index_alias_fail_1] are empty"));
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
        assertEquals(3, unmappedFieldAliases.size());
    }

    public void testGetMappingsView_index_pattern_two_indices_Success() throws IOException {

        String testIndexName1 = "get_mappings_view_index11";
        String testIndexName2 = "get_mappings_view_index22";
        String indexPattern = "get_mappings_view_index*";
        createSampleIndex(testIndexName1);
        createSampleIndex(testIndexName2);
        indexDoc(testIndexName2, "987654", "{ \"extra_field\": 12345 }");

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", indexPattern);
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
        assertEquals(7, unmappedIndexFields.size());
        // Verify that we got Mappings View of concrete index testIndexName2 because it is newest of all under this alias
        Optional<String> extraField = unmappedIndexFields.stream().filter(e -> e.equals("extra_field")).findFirst();
        assertTrue(extraField.isPresent());
        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(3, unmappedFieldAliases.size());
    }

    public void testGetMappingsView_alias_without_writeindex_Success() throws IOException {

        String testIndexName1 = "get_mappings_view_index11";
        String testIndexName2 = "get_mappings_view_index22";
        String indexAlias = "index_alias";
        createSampleIndex(testIndexName1, Settings.EMPTY, "\"" + indexAlias + "\":{}");
        createSampleIndex(testIndexName2, Settings.EMPTY, "\"" + indexAlias + "\":{}");
        indexDoc(testIndexName2, "987654", "{ \"extra_field\": 12345 }");

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", indexAlias);
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
        assertEquals(7, unmappedIndexFields.size());
        // Verify that we got Mappings View of concrete index testIndexName2 because it is newest of all under this alias
        Optional<String> extraField = unmappedIndexFields.stream().filter(e -> e.equals("extra_field")).findFirst();
        assertTrue(extraField.isPresent());
        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(3, unmappedFieldAliases.size());
    }

    public void testGetMappingsView_alias_with_writeindex_Success() throws IOException {

        String testIndexName1 = "get_mappings_view_index11";
        String testIndexName2 = "get_mappings_view_index22";
        String indexAlias = "index_alias";

        createSampleIndex(testIndexName2, Settings.EMPTY, "\"" + indexAlias + "\":{}");
        createSampleIndex(testIndexName1, Settings.EMPTY, "\"" + indexAlias + "\":{ \"is_write_index\":true }");

        // Add extra field by inserting doc to index #1 to differentiate two easier
        indexDoc(testIndexName1, "987654", "{ \"extra_field\": 12345 }");

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", indexAlias);
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
        assertEquals(7, unmappedIndexFields.size());
        // Verify that we got Mappings View of concrete index testIndexName2 because it is newest of all under this alias
        Optional<String> extraField = unmappedIndexFields.stream().filter(e -> e.equals("extra_field")).findFirst();
        assertTrue(extraField.isPresent());
        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(3, unmappedFieldAliases.size());
    }

    public void testGetMappingsView_datastream_one_backing_index_Success() throws IOException {

        String datastreamName = "my_data_stream";
        createSampleDatastream(datastreamName);
        // Execute GetMappingsViewAction to add alias mapping for index
        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", datastreamName);
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
        assertEquals(7, unmappedIndexFields.size());
        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(3, unmappedFieldAliases.size());

        deleteDatastream(datastreamName);
    }

    public void testGetMappingsView_datastream_two_backing_index_Success() throws IOException {

        String datastreamName = "my_data_stream";
        createSampleDatastream(datastreamName);

        // Modify index template to change mappings and then rollover
        String indexMapping =
                "    \"properties\": {" +
                        "        \"@timestamp\": {" +
                        "          \"type\": \"date\"" +
                        "        }," +
                        "        \"netflow.source_ipv4_address\": {" +
                        "          \"type\": \"ip\"" +
                        "        }" +
                        "}";

        String indexTemplateRequest = "{\n" +
                "  \"index_patterns\": [\"" + datastreamName + "*\"],\n" +
                "  \"data_stream\": { },\n" +
                "  \"template\": {\n" +
                "    \"mappings\" : {" + indexMapping + "}\n" +
                "  }," +
                "  \"priority\": 500\n" +
                "}";


        Response response = makeRequest(client(), "PUT", "_index_template/" + datastreamName + "-template", Collections.emptyMap(),
                new StringEntity(indexTemplateRequest), new BasicHeader("Content-Type", "application/json"));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        doRollover(datastreamName);

        // Execute GetMappingsViewAction to add alias mapping for index
        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", datastreamName);
        request.addParameter("rule_topic", "netflow");
        response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = responseAsMap(response);
        // Verify alias mappings
        Map<String, Object> props = (Map<String, Object>) respMap.get("properties");
        assertEquals(1, props.size());
        assertTrue(props.containsKey("source.ip"));
        // Verify unmapped index fields

        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(6, unmappedFieldAliases.size());

        deleteDatastream(datastreamName);
    }

    public void testCreateMappings_withIndexPattern_success() throws IOException {
        String indexName1 = "test_index_1";
        String indexName2 = "test_index_2";
        String indexPattern = "test_index*";

        createIndex(indexName1, Settings.EMPTY, null);
        createIndex(indexName2, Settings.EMPTY, null);

        client().performRequest(new Request("POST", "_refresh"));

        // Insert sample doc
        String sampleDoc = "{" +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.destination_transport_port\":1234," +
                "  \"netflow.destination_ipv4_address\":\"10.53.111.14\"," +
                "  \"netflow.source_transport_port\":4444" +
                "}";

        indexDoc(indexName1, "1", sampleDoc);
        indexDoc(indexName2, "1", sampleDoc);

        client().performRequest(new Request("POST", "_refresh"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{ \"index_name\":\"" + indexPattern + "\"," +
                        "  \"rule_topic\":\"netflow\", " +
                        "  \"partial\":true" +
                        "}"
        );
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    public void testCreateMappings_withIndexPattern_differentMappings_success() throws IOException {
        String indexName1 = "test_index_1";
        String indexName2 = "test_index_2";
        String indexPattern = "test_index*";

        createIndex(indexName1, Settings.EMPTY, null);
        createIndex(indexName2, Settings.EMPTY, null);

        client().performRequest(new Request("POST", "_refresh"));

        // Insert sample docs
        String sampleDoc1 = "{" +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.destination_transport_port\":1234," +
                "  \"netflow.source_transport_port\":4444" +
                "}";
        String sampleDoc2 = "{" +
                "  \"netflow.destination_transport_port\":1234," +
                "  \"netflow.destination_ipv4_address\":\"10.53.111.14\"" +
                "}";
        indexDoc(indexName1, "1", sampleDoc1);
        indexDoc(indexName2, "1", sampleDoc2);

        client().performRequest(new Request("POST", "_refresh"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{ \"index_name\":\"" + indexPattern + "\"," +
                        "  \"rule_topic\":\"netflow\", " +
                        "  \"partial\":true" +
                        "}"
        );
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    public void testCreateMappings_withIndexPattern_oneNoMatches_success() throws IOException {
        String indexName1 = "test_index_1";
        String indexName2 = "test_index_2";
        String indexPattern = "test_index*";

        createIndex(indexName1, Settings.EMPTY, null);
        createIndex(indexName2, Settings.EMPTY, null);

        client().performRequest(new Request("POST", "_refresh"));

        // Insert sample docs
        String sampleDoc1 = "{" +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.destination_transport_port\":1234," +
                "  \"netflow.source_transport_port\":4444" +
                "}";
        String sampleDoc2 = "{" +
                "  \"netflow11.destination33_transport_port\":1234," +
                "  \"netflow11.destination33_ipv4_address\":\"10.53.111.14\"" +
                "}";
        indexDoc(indexName1, "1", sampleDoc1);
        indexDoc(indexName2, "1", sampleDoc2);

        client().performRequest(new Request("POST", "_refresh"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{ \"index_name\":\"" + indexPattern + "\"," +
                        "  \"rule_topic\":\"netflow\", " +
                        "  \"partial\":true" +
                        "}"
        );
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    public void testCreateMappings_withIndexPattern_oneNoMappings_failure() throws IOException {
        String indexName1 = "test_index_1";
        String indexName2 = "test_index_2";
        String indexPattern = "test_index*";

        createIndex(indexName1, Settings.EMPTY, null);
        createIndex(indexName2, Settings.EMPTY, null);

        client().performRequest(new Request("POST", "_refresh"));

        // Insert sample docs
        String sampleDoc1 = "{" +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.destination_transport_port\":1234," +
                "  \"netflow.source_transport_port\":4444" +
                "}";
        indexDoc(indexName1, "1", sampleDoc1);

        client().performRequest(new Request("POST", "_refresh"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{ \"index_name\":\"" + indexPattern + "\"," +
                        "  \"rule_topic\":\"netflow\", " +
                        "  \"partial\":true" +
                        "}"
        );
        try {
            client().performRequest(request);
            fail("expected 500 failure!");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getResponse().getStatusLine().getStatusCode());
        }

    }

    private void createSampleIndex(String indexName) throws IOException {
        createSampleIndex(indexName, Settings.EMPTY, null);
    }

    private void createSampleIndex(String indexName, Settings settings, String aliases) throws IOException {
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

        createIndex(indexName, settings, indexMapping, aliases);

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

    private void createSampleDatastream(String datastreamName) throws IOException {
        String indexMapping =
                "    \"properties\": {" +
                        "        \"@timestamp\": {" +
                        "          \"type\": \"date\"" +
                        "        }," +
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


        // Create index template
        String indexTemplateRequest = "{\n" +
                "  \"index_patterns\": [\"" + datastreamName + "*\"],\n" +
                "  \"data_stream\": { },\n" +
                "  \"template\": {\n" +
                "    \"mappings\" : {" + indexMapping + "}\n" +
                "  }," +
                "  \"priority\": 500\n" +
                "}";


        Response response = makeRequest(client(), "PUT", "_index_template/" + datastreamName + "-template", Collections.emptyMap(),
                new StringEntity(indexTemplateRequest), new BasicHeader("Content-Type", "application/json"));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        // Insert sample doc
        String sampleDoc = "{" +
                "  \"@timestamp\":\"2023-05-06T16:21:15.000Z\"," +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.destination_transport_port\":1234," +
                "  \"netflow.destination_ipv4_address\":\"10.53.111.14\"," +
                "  \"netflow.source_transport_port\":4444" +
                "}";

        // Index doc
        Request indexRequest = new Request("POST", datastreamName + "/_doc?refresh=wait_for");
        indexRequest.setJsonEntity(sampleDoc);
        response = client().performRequest(indexRequest);
        assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
        // Refresh everything
        response = client().performRequest(new Request("POST", "_refresh"));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    private void deleteDatastream(String datastreamName) throws IOException {
        Request indexRequest = new Request("DELETE", "_data_stream/" + datastreamName);
        Response response = client().performRequest(indexRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    private final String DNS_SAMPLE = "dns-sample.json";
    private final String CLOUDTRAIL_SAMPLE = "cloudtrail-sample.json";
    private final String CLOUDTRAIL_SAMPLE_S3 = "cloudtrail-sample-s3.json";


    private final String DNS_MAPPINGS = "OSMapping/dns/mappings.json";
    private final String CLOUDTRAIL_MAPPINGS = "OSMapping/cloudtrail/mappings.json";
    private final String S3_MAPPINGS = "OSMapping/s3/mappings.json";

    private final String NETWORK_MAPPINGS = "OSMapping/network/mappings.json";
    private final String LINUX_MAPPINGS = "OSMapping/linux/mappings.json";
    private final String WINDOWS_MAPPINGS = "OSMapping/windows/mappings.json";
    private final String APACHE_ACCESS_MAPPINGS = "OSMapping/apache_access/mappings.json";
    private final String AD_LDAP_MAPPINGS = "OSMapping/ad_ldap/mappings.json";

    private String readResource(String name) throws IOException {
        try (InputStream inputStream = SecurityAnalyticsPlugin.class.getClassLoader().getResourceAsStream(name)) {
            if (inputStream == null) {
                throw new IOException("Resource not found: " + name);
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                return reader.lines().collect(Collectors.joining("\n"));
            }
        }
    }

    public void testReadResource() throws IOException {
        String content = readResource(DNS_MAPPINGS);
        assertTrue(content.contains("properties"));
    }

    public void testCreateCloudTrailMappingS3() throws IOException {
        String INDEX_NAME = "test_create_cloudtrail_s3_mapping_index";

        createSampleIndex(INDEX_NAME);
        // Sample dns document
        String sampleDoc = readResource(CLOUDTRAIL_SAMPLE_S3);
        // Index doc
        Request indexRequest = new Request("POST", INDEX_NAME + "/_doc?refresh=wait_for");
        indexRequest.setJsonEntity(sampleDoc);
        //Generate automatic mappings my inserting doc
        Response response = client().performRequest(indexRequest);
        //Get the mappings being tested
        String indexMapping = readResource(S3_MAPPINGS);
        //Parse the mappings
        XContentParser parser = JsonXContent.jsonXContent
                .createParser(
                        NamedXContentRegistry.EMPTY,
                        DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                        indexMapping);
        Map<String, Object> mappings = (Map<String, Object>) parser.map().get("properties");
        GetMappingsResponse getMappingsResponse = SecurityAnalyticsClientUtils.executeGetMappingsRequest(INDEX_NAME);

        MappingsTraverser mappingsTraverser = new MappingsTraverser(getMappingsResponse.getMappings().iterator().next().value);
        List<String> flatProperties = mappingsTraverser.extractFlatNonAliasFields();
        assertTrue(flatProperties.contains("aws.cloudtrail.eventName"));
        assertTrue(flatProperties.contains("aws.cloudtrail.eventSource"));
        //Loop over the mappings and run update request for each one specifying the index to be updated
        mappings.entrySet().forEach(entry -> {
            String key = entry.getKey();
            String path = ((Map<String, Object>) entry.getValue()).get("path").toString();
            try {
                Request updateRequest = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
                updateRequest.setJsonEntity(Strings.toString(XContentFactory.jsonBuilder().map(Map.of(
                        "index_name", INDEX_NAME,
                        "field", path,
                        "alias", key))));
                Response apiResponse = client().performRequest(updateRequest);
                assertEquals(HttpStatus.SC_OK, apiResponse.getStatusLine().getStatusCode());

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });

        // Refresh everything
        response = client().performRequest(new Request("POST", "_refresh"));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    public void testCreateCloudTrailMapping() throws IOException {
        String INDEX_NAME = "test_create_cloudtrail_mapping_index";

        createSampleIndex(INDEX_NAME);
        // Sample dns document
        String sampleDoc = readResource(CLOUDTRAIL_SAMPLE);
        // Index doc
        Request indexRequest = new Request("POST", INDEX_NAME + "/_doc?refresh=wait_for");
        indexRequest.setJsonEntity(sampleDoc);
        //Generate automatic mappings my inserting doc
        Response response = client().performRequest(indexRequest);
        //Get the mappings being tested
        String indexMapping = readResource(CLOUDTRAIL_MAPPINGS);
        //Parse the mappings
        XContentParser parser = JsonXContent.jsonXContent
                .createParser(
                        NamedXContentRegistry.EMPTY,
                        DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                        indexMapping);
        Map<String, Object> mappings = (Map<String, Object>) parser.map().get("properties");
        GetMappingsResponse getMappingsResponse = SecurityAnalyticsClientUtils.executeGetMappingsRequest(INDEX_NAME);

        MappingsTraverser mappingsTraverser = new MappingsTraverser(getMappingsResponse.getMappings().iterator().next().value);
        List<String> flatProperties = mappingsTraverser.extractFlatNonAliasFields();
        assertTrue(flatProperties.contains("aws.cloudtrail.eventType"));
        assertTrue(flatProperties.contains("aws.cloudtrail.eventSource"));
        assertTrue(flatProperties.contains("aws.cloudtrail.requestParameters.arn"));
        assertTrue(flatProperties.contains("aws.cloudtrail.requestParameters.attribute"));
        assertTrue(flatProperties.contains("aws.cloudtrail.requestParameters.userName"));
        assertTrue(flatProperties.contains("aws.cloudtrail.userIdentity.arn"));
        assertTrue(flatProperties.contains("aws.cloudtrail.userIdentity.type"));
        assertTrue(flatProperties.contains("aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.type"));
        //Loop over the mappings and run update request for each one specifying the index to be updated
        mappings.entrySet().forEach(entry -> {
            String key = entry.getKey();
            String path = ((Map<String, Object>) entry.getValue()).get("path").toString();
            try {
                Request updateRequest = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
                updateRequest.setJsonEntity(Strings.toString(XContentFactory.jsonBuilder().map(Map.of(
                        "index_name", INDEX_NAME,
                        "field", path,
                        "alias", key))));
                Response apiResponse = client().performRequest(updateRequest);
                assertEquals(HttpStatus.SC_OK, apiResponse.getStatusLine().getStatusCode());

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });

        // Refresh everything
        response = client().performRequest(new Request("POST", "_refresh"));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }
    public void testCreateDNSMapping() throws IOException{
        String INDEX_NAME = "test_create_cloudtrail_mapping_index";

        createSampleIndex(INDEX_NAME);
        // Sample dns document
        String dnsSampleDoc = readResource(DNS_SAMPLE);
        // Index doc
        Request indexRequest = new Request("POST", INDEX_NAME + "/_doc?refresh=wait_for");
        indexRequest.setJsonEntity(dnsSampleDoc);
        //Generate automatic mappings my inserting doc
        Response response = client().performRequest(indexRequest);
        //Get the mappings being tested
        String indexMapping = readResource(DNS_MAPPINGS);
        //Parse the mappings
        XContentParser parser = JsonXContent.jsonXContent
                .createParser(
                        NamedXContentRegistry.EMPTY,
                        DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                        indexMapping);
        Map<String, Object> mappings = (Map<String, Object>) parser.map().get("properties");
        GetMappingsResponse getMappingsResponse = SecurityAnalyticsClientUtils.executeGetMappingsRequest(INDEX_NAME);

        MappingsTraverser mappingsTraverser = new MappingsTraverser(getMappingsResponse.getMappings().iterator().next().value);
        List<String> flatProperties = mappingsTraverser.extractFlatNonAliasFields();
        assertTrue(flatProperties.contains("dns.answers.type"));
        assertTrue(flatProperties.contains("dns.question.name"));
        assertTrue(flatProperties.contains("dns.question.registered_domain"));

        //Loop over the mappings and run update request for each one specifying the index to be updated
        mappings.entrySet().forEach(entry -> {
            String key = entry.getKey();
            if("timestamp".equals(key))
                return;
            String path = ((Map<String, Object>) entry.getValue()).get("path").toString();
            try {
                Request updateRequest = new Request("PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
                updateRequest.setJsonEntity(Strings.toString(XContentFactory.jsonBuilder().map(Map.of(
                        "index_name", INDEX_NAME,
                        "field", path,
                        "alias", key))));
                Response apiResponse = client().performRequest(updateRequest);
                assertEquals(HttpStatus.SC_OK, apiResponse.getStatusLine().getStatusCode());

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });

        // Refresh everything
        response = client().performRequest(new Request("POST", "_refresh"));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

}
