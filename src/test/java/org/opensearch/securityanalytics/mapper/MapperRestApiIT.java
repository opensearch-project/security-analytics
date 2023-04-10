/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.Assert;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.common.Strings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsClientUtils;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.test.OpenSearchTestCase;


import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.MAPPER_BASE_URI;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;

public class MapperRestApiIT extends SecurityAnalyticsRestTestCase {


    public void testGetMappingSuccess() throws IOException {
        String testIndexName1 = "my_index_1";
        String testIndexName2 = "my_index_2";
        String testIndexPattern = "my_index*";

        createSampleIndex(testIndexName1);
        createSampleIndex(testIndexName2);

        createMappingsAPI(testIndexName2, "netflow");

        Request request = new Request("GET", MAPPER_BASE_URI + "?index_name=" + testIndexPattern);
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = (Map<String, Object>) responseAsMap(response);
        // Assert that indexName returned is one passed by user
        assertTrue(respMap.containsKey(testIndexPattern));
    }

    public void testGetMappingSuccess_1() throws IOException {
        String testIndexName1 = "my_index_1";
        String testIndexPattern = "my_index*";

        createIndex(testIndexName1, Settings.EMPTY);

        String sampleDoc = "{\n" +
                "  \"lvl1field\": 12345,\n" +
                "  \"source1.ip\": \"12345\",\n" +
                "  \"source1.port\": 55,\n" +
                "  \"some.very.long.field.name\": \"test\"\n" +
                "}";

        indexDoc(testIndexName1, "1", sampleDoc);
        // puts mappings with timestamp alias
        String createMappingsRequest = "{\"index_name\":\"my_index*\",\"rule_topic\":\"windows\",\"partial\":true,\"alias_mappings\":{\"properties\":{\"timestamp\":{\"type\":\"alias\",\"path\":\"lvl1field\"},\"winlog-computer_name\":{\"type\":\"alias\",\"path\":\"source1.port\"},\"winlog-event_data-AuthenticationPackageName\":{\"type\":\"alias\",\"path\":\"source1.ip\"},\"winlog-event_data-Company\":{\"type\":\"alias\",\"path\":\"some.very.long.field.name\"}}}}";

        Request request = new Request("POST", MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(createMappingsRequest);
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        request = new Request("GET", MAPPER_BASE_URI + "?index_name=" + testIndexPattern);
        response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = (Map<String, Object>) responseAsMap(response);
        Map<String, Object> props = (Map<String, Object>)((Map<String, Object>) respMap.get(testIndexPattern)).get("mappings");
        props = (Map<String, Object>) props.get("properties");
        assertEquals(4, props.size());
    }

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
            assertTrue(e.getMessage().contains("No applied aliases found"));
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

        // Execute GetMappingsViewAction to add alias mapping for index
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

    public void testCreateMappings_withDatastream_success() throws IOException {
        String datastream = "test_datastream";

        String datastreamMappings = "\"properties\": {" +
                "  \"@timestamp\":{ \"type\": \"date\" }," +
                "  \"netflow.destination_transport_port\":{ \"type\": \"long\" }," +
                "  \"netflow.destination_ipv4_address\":{ \"type\": \"ip\" }" +
                "}";

        createSampleDatastream(datastream, datastreamMappings);

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingsAPI(datastream, "netflow");

        // Verify mappings
        Map<String, Object> props = getIndexMappingsAPIFlat(datastream);
        assertEquals(5, props.size());
        assertTrue(props.containsKey("@timestamp"));
        assertTrue(props.containsKey("netflow.destination_transport_port"));
        assertTrue(props.containsKey("netflow.destination_ipv4_address"));
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("destination.port"));

        // Verify that index template applied mappings
        Response response = makeRequest(client(), "POST", datastream + "/_rollover", Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Insert doc to index to add additional fields to mapping
        String sampleDoc = "{" +
                "  \"@timestamp\":\"2023-01-06T00:05:00\"," +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.source_transport_port\":4444" +
                "}";

        indexDoc(datastream, "2", sampleDoc);

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingsAPI(datastream, "netflow");

        String writeIndex = getDatastreamWriteIndex(datastream);

        // Verify mappings
        props = getIndexMappingsAPIFlat(writeIndex);
        assertEquals(9, props.size());
        assertTrue(props.containsKey("@timestamp"));
        assertTrue(props.containsKey("netflow.source_ipv4_address"));
        assertTrue(props.containsKey("netflow.source_transport_port"));
        assertTrue(props.containsKey("netflow.destination_transport_port"));
        assertTrue(props.containsKey("netflow.destination_ipv4_address"));
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("destination.port"));
        assertTrue(props.containsKey("source.ip"));
        assertTrue(props.containsKey("source.port"));

        // Get applied mappings
        props = getIndexMappingsSAFlat(datastream);
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("destination.port"));
        assertTrue(props.containsKey("source.ip"));
        assertTrue(props.containsKey("source.port"));

        deleteDatastreamAPI(datastream);
    }

    public void testCreateMappings_withDatastream_withTemplateField_success() throws IOException {
        String datastream = "test_datastream";

        String datastreamMappings = "\"properties\": {" +
                "  \"@timestamp\":{ \"type\": \"date\" }," +
                "  \"netflow.destination_transport_port\":{ \"type\": \"long\" }," +
                "  \"netflow.destination_ipv4_address\":{ \"type\": \"ip\" }" +
                "}";

        createSampleDatastream(datastream, datastreamMappings, false);

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingsAPI(datastream, "netflow");

        // Verify mappings
        Map<String, Object> props = getIndexMappingsAPIFlat(datastream);
        assertEquals(5, props.size());
        assertTrue(props.containsKey("@timestamp"));
        assertTrue(props.containsKey("netflow.destination_transport_port"));
        assertTrue(props.containsKey("netflow.destination_ipv4_address"));
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("destination.port"));

        // Verify that index template applied mappings
        Response response = makeRequest(client(), "POST", datastream + "/_rollover", Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Insert doc to index to add additional fields to mapping
        String sampleDoc = "{" +
                "  \"@timestamp\":\"2023-01-06T00:05:00\"," +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.source_transport_port\":4444" +
                "}";

        indexDoc(datastream, "2", sampleDoc);

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingsAPI(datastream, "netflow");

        String writeIndex = getDatastreamWriteIndex(datastream);

        // Verify mappings
        props = getIndexMappingsAPIFlat(writeIndex);
        assertEquals(9, props.size());
        assertTrue(props.containsKey("@timestamp"));
        assertTrue(props.containsKey("netflow.source_ipv4_address"));
        assertTrue(props.containsKey("netflow.source_transport_port"));
        assertTrue(props.containsKey("netflow.destination_transport_port"));
        assertTrue(props.containsKey("netflow.destination_ipv4_address"));
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("destination.port"));
        assertTrue(props.containsKey("source.ip"));
        assertTrue(props.containsKey("source.port"));

        // Get applied mappings
        props = getIndexMappingsSAFlat(datastream);
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("destination.port"));
        assertTrue(props.containsKey("source.ip"));
        assertTrue(props.containsKey("source.port"));

        deleteDatastreamAPI(datastream);
    }

    public void testCreateMappings_withIndexPattern_existing_indexTemplate_update_success() throws IOException {
        String indexName1 = "test_index_1";
        String indexName2 = "test_index_2";
        String indexName3 = "test_index_3";

        String indexPattern = "test_index*";

        String componentTemplateMappings = "\"properties\": {" +
                "  \"netflow.destination_transport_port\":{ \"type\": \"long\" }," +
                "  \"netflow.destination_ipv4_address\":{ \"type\": \"ip\" }" +
                "}";

        // Setup index_template
        createComponentTemplateWithMappings(
                IndexTemplateUtils.computeComponentTemplateName(indexPattern),
                componentTemplateMappings
        );

        createComposableIndexTemplate(
                IndexTemplateUtils.computeIndexTemplateName(indexPattern),
                List.of(indexPattern),
                IndexTemplateUtils.computeComponentTemplateName(indexPattern),
                null,
                false
        );

        createIndex(indexName1, Settings.EMPTY, null);

        // Execute CreateMappingsAction to apply alias mappings - index template should be updated
        createMappingsAPI(indexPattern, "netflow");

        // Create new index to verify that index template is updated
        createIndex(indexName2, Settings.EMPTY, null);

        // Verify that template applied mappings
        Map<String, Object> props = getIndexMappingsAPIFlat(indexName2);
        assertEquals(4, props.size());
        assertTrue(props.containsKey("netflow.destination_transport_port"));
        assertTrue(props.containsKey("netflow.destination_ipv4_address"));
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("destination.port"));

        // Verify our GetIndexMappings -- applied mappings
        props = getIndexMappingsSAFlat(indexPattern);
        assertEquals(2, props.size());
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("destination.port"));


        // Insert doc to index to add additional fields to mapping
        String sampleDoc = "{" +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.source_transport_port\":4444" +
                "}";

        indexDoc(indexName2, "1", sampleDoc);

        // Call CreateMappings API and expect index template to be updated with 2 additional aliases
        createMappingsAPI(indexPattern, "netflow");

        // Create new index to verify that index template was updated correctly
        createIndex(indexName3, Settings.EMPTY, null);

        // Verify mappings
        props = getIndexMappingsAPIFlat(indexName3);
        assertEquals(8, props.size());
        assertTrue(props.containsKey("source.ip"));
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("source.port"));
        assertTrue(props.containsKey("destination.port"));
        assertTrue(props.containsKey("netflow.source_transport_port"));
        assertTrue(props.containsKey("netflow.source_ipv4_address"));
        assertTrue(props.containsKey("netflow.destination_transport_port"));
        assertTrue(props.containsKey("netflow.destination_ipv4_address"));

        // Verify our GetIndexMappings -- applied mappings
        props = getIndexMappingsSAFlat(indexPattern);
        assertEquals(4, props.size());
        assertTrue(props.containsKey("source.ip"));
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("source.port"));
        assertTrue(props.containsKey("destination.port"));
    }

    public void testCreateMappings_withIndexPattern_differentMappings_indexTemplateCleanup_success() throws IOException, InterruptedException {
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
        createMappingsAPI(indexPattern, "netflow");

        DetectorInput input = new DetectorInput("", List.of(indexPattern), List.of(),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        String detectorId = createDetector(TestHelpers.randomDetectorWithInputs(List.of((input))));

        refreshAllIndices();

        List<Object> componentTemplates = getAllComponentTemplates();
        assertEquals(1, componentTemplates.size());
        List<Object> composableIndexTemplates = getAllComposableIndexTemplates();
        assertEquals(2, composableIndexTemplates.size());

        deleteDetector(detectorId);

        // Wait for clusterState update to be published/applied
        OpenSearchTestCase.waitUntil(() -> {
            try {
                List<Object> ct = getAllComponentTemplates();
                if (ct.size() == 0) {
                    return true;
                } else {
                    return false;
                }
            } catch (IOException e) {

            }
            return false;
        });
        OpenSearchTestCase.waitUntil(() -> {
            try {
                List<Object> cct = getAllComposableIndexTemplates();
                if (cct.size() == 1) {
                    return true;
                } else {
                    return false;
                }
            } catch (IOException e) {

            }
            return false;
        });

        componentTemplates = getAllComponentTemplates();
        assertEquals(0, componentTemplates.size());
        composableIndexTemplates = getAllComposableIndexTemplates();
        assertEquals(1, composableIndexTemplates.size());
    }

    public void testCreateMappings_withIndexPattern_indexTemplate_createAndUpdate_success() throws IOException {
        String indexName1 = "test_index_1";
        String indexName2 = "test_index_2";
        String indexName3 = "test_index_3";
        String indexName4 = "test_index_4";

        String indexPattern = "test_index*";

        createIndex(indexName1, Settings.EMPTY, null);
        createIndex(indexName2, Settings.EMPTY, null);

        client().performRequest(new Request("POST", "_refresh"));

        // Insert sample doc
        String sampleDoc1 = "{" +
                "  \"netflow.destination_transport_port\":1234," +
                "  \"netflow.destination_ipv4_address\":\"10.53.111.14\"" +
                "}";

        indexDoc(indexName1, "1", sampleDoc1);
        indexDoc(indexName2, "1", sampleDoc1);

        client().performRequest(new Request("POST", "_refresh"));

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingsAPI(indexPattern, "netflow");

        // Verify that index template is up
        createIndex(indexName3, Settings.EMPTY, null);

        // Execute CreateMappingsAction to add alias mapping for index
        Request request = new Request("GET", indexName3 + "/_mapping");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = (Map<String, Object>) responseAsMap(response).get(indexName3);

        MappingsTraverser mappingsTraverser = new MappingsTraverser((Map<String, Object>) respMap.get("mappings"), Set.of());
        Map<String, Object> flatMappings = mappingsTraverser.traverseAndCopyAsFlat();
        // Verify mappings
        Map<String, Object> props = (Map<String, Object>) flatMappings.get("properties");
        assertEquals(4, props.size());
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("destination.port"));
        assertTrue(props.containsKey("netflow.destination_transport_port"));
        assertTrue(props.containsKey("netflow.destination_ipv4_address"));

        String sampleDoc2 = "{" +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.destination_transport_port\":1234," +
                "  \"netflow.destination_ipv4_address\":\"10.53.111.14\"," +
                "  \"netflow.source_transport_port\":4444" +
                "}";

        indexDoc(indexName3, "1", sampleDoc2);

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingsAPI(indexPattern, "netflow");

        // Verify that index template is updated
        createIndex(indexName4, Settings.EMPTY, null);

        // Execute CreateMappingsAction to add alias mapping for index
        request = new Request("GET", indexName4 + "/_mapping");
        response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        respMap = (Map<String, Object>) responseAsMap(response).get(indexName4);

        mappingsTraverser = new MappingsTraverser((Map<String, Object>) respMap.get("mappings"), Set.of());
        flatMappings = mappingsTraverser.traverseAndCopyAsFlat();
        // Verify mappings
        props = (Map<String, Object>) flatMappings.get("properties");
        assertEquals(8, props.size());
        assertTrue(props.containsKey("source.ip"));
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("source.port"));
        assertTrue(props.containsKey("destination.port"));
        assertTrue(props.containsKey("netflow.source_transport_port"));
        assertTrue(props.containsKey("netflow.source_ipv4_address"));
        assertTrue(props.containsKey("netflow.destination_transport_port"));
        assertTrue(props.containsKey("netflow.destination_ipv4_address"));

        // Verify applied mappings
        props = getIndexMappingsSAFlat(indexName4);
        assertEquals(4, props.size());
        assertTrue(props.containsKey("source.ip"));
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("source.port"));
        assertTrue(props.containsKey("destination.port"));
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
        try {
            createMappingsAPI(indexPattern, "netflow");
            fail("expected 500 failure!");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getResponse().getStatusLine().getStatusCode());
        }

    }

    public void testGetMappingsView_index_pattern_two_indices_Success() throws IOException {

        String testIndexName1 = "get_mappings_view_index111";
        String testIndexName2 = "get_mappings_view_index122";
        String testIndexName3 = "get_mappings_view_index";

        String indexPattern = "get_mappings_view_index1*";
        String indexPattern2 = "get_mappings_view_index*";

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

    public void testCreateMappings_withIndexPattern_conflictingTemplates_success() throws IOException {
        String indexName1 = "test_index_11";
        String indexName2 = "test_index_12";
        String indexName3 = "test_index_13";
        String indexName4 = "test_index44";
        String indexPattern1 = "test_index_1*";
        String indexPattern2 = "test_index*";

        createIndex(indexName1, Settings.EMPTY, null);
        createIndex(indexName2, Settings.EMPTY, null);

        client().performRequest(new Request("POST", "_refresh"));

        // Insert sample doc
        String sampleDoc = "{" +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.destination_transport_port\":1234" +
                "}";

        indexDoc(indexName1, "1", sampleDoc);
        indexDoc(indexName2, "1", sampleDoc);

        client().performRequest(new Request("POST", "_refresh"));

        // Execute CreateMappingsAction with first index pattern
        createMappingsAPI(indexPattern1, "netflow");

        createIndex(indexName3, Settings.EMPTY, null);

        // Insert sample doc
        String sampleDoc2 = "{" +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.destination_transport_port\":1234," +
                "  \"netflow.destination_ipv4_address\":\"10.53.111.14\"," +
                "  \"netflow.source_transport_port\":4444" +
                "}";

        indexDoc(indexName3, "1", sampleDoc2);

        // Execute CreateMappingsAction with conflicting index pattern - expect template to be updated
        createMappingsAPI(indexPattern2, "netflow");

        createIndex(indexName4, Settings.EMPTY, null);
        // Verify with GET _mapping
        Map<String, Object> props = getIndexMappingsAPIFlat(indexName4);
        assertEquals(8, props.size());
        // Verify with SA's GetIndexMappings
        props = getIndexMappingsSAFlat(indexName4);
        assertEquals(4, props.size());
        assertTrue(props.containsKey("source.ip"));
        assertTrue(props.containsKey("source.port"));
        assertTrue(props.containsKey("destination.ip"));
        assertTrue(props.containsKey("destination.port"));
    }

    public void testCreateMappings_withIndexPattern_conflictingTemplates_failure_1() throws IOException {
        String indexName1 = "test_index_11";
        String indexName2 = "test_index_12";
        String indexName3 = "test_index_13";
        String indexName4 = "test_index44";
        String indexPattern1 = "test_index_1*";
        String indexPattern2 = "test_index*";

        createIndex(indexName1, Settings.EMPTY, null);
        createIndex(indexName2, Settings.EMPTY, null);

        client().performRequest(new Request("POST", "_refresh"));

        // Insert sample doc
        String sampleDoc = "{" +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.destination_transport_port\":1234" +
                "}";

        indexDoc(indexName1, "1", sampleDoc);
        indexDoc(indexName2, "1", sampleDoc);

        client().performRequest(new Request("POST", "_refresh"));

        // Execute CreateMappingsAction with first index pattern
        createMappingsAPI(indexPattern1, "netflow");

        // User-create template with conflicting pattern but higher priority
        createComponentTemplateWithMappings("user_component_template", "\"properties\": { \"some_field\": { \"type\": \"long\" } }");
        createComposableIndexTemplate("user_custom_template", List.of("test_index_111111*"), "user_component_template", null, false, 100);

        // Execute CreateMappingsAction and expect 2 conflicting templates and failure
        try {
            createMappingsAPI(indexPattern2, "netflow");
        } catch (ResponseException e) {
            assertTrue(e.getMessage().contains("Found conflicting templates: [user_custom_template, .opensearch-sap-alias-mappings-index-template-test_index_1]"));
        }
    }

    public void testCreateMappings_withIndexPattern_conflictingTemplates_failure_2() throws IOException {
        String indexName1 = "test_index_11";
        String indexName2 = "test_index_12";
        String indexName3 = "test_index_13";
        String indexName4 = "test_index44";
        String indexPattern1 = "test_index_1*";
        String indexPattern2 = "test_index*";

        createIndex(indexName1, Settings.EMPTY, null);
        createIndex(indexName2, Settings.EMPTY, null);

        client().performRequest(new Request("POST", "_refresh"));

        // Insert sample doc
        String sampleDoc = "{" +
                "  \"netflow.source_ipv4_address\":\"10.50.221.10\"," +
                "  \"netflow.destination_transport_port\":1234" +
                "}";

        indexDoc(indexName1, "1", sampleDoc);
        indexDoc(indexName2, "1", sampleDoc);

        client().performRequest(new Request("POST", "_refresh"));


        // User-create template with conflicting pattern but higher priority
        createComponentTemplateWithMappings("user_component_template", "\"properties\": { \"some_field\": { \"type\": \"long\" } }");
        createComposableIndexTemplate("user_custom_template", List.of("test_index_111111*"), "user_component_template", null, false, 100);

        // Execute CreateMappingsAction and expect conflict with 1 user template
        try {
            createMappingsAPI(indexPattern2, "netflow");
        } catch (ResponseException e) {
            assertTrue(e.getMessage().contains("Found conflicting template: [user_custom_template]"));
        }
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
    private final String CLOUDTRAIL_SAMPLE_S3 = "s3-sample.json";


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


    public void testTraverseAndCopy() {

        try {
            String indexName = "my_test_index";

            String indexMappingJSON = "" +
                    "    \"properties\": {" +
                    "        \"netflow.event_data.SourceAddress\": {" +
                    "          \"type\": \"ip\"" +
                    "        }," +
                    "        \"type\": {" +
                    "          \"type\": \"integer\"" +
                    "        }," +
                    "        \"netflow.event_data.DestinationPort\": {" +
                    "          \"type\": \"integer\"" +
                    "        }," +
                    "        \"netflow.event.stop\": {" +
                    "          \"type\": \"integer\"" +
                    "        }," +
                    "        \"netflow.event.start\": {" +
                    "          \"type\": \"long\"" +
                    "        }," +
                    "        \"plain1\": {" +
                    "          \"type\": \"integer\"" +
                    "        }," +
                    "        \"user\":{" +
                    "          \"type\":\"nested\"," +
                    "            \"properties\":{" +
                    "              \"first\":{" +
                    "                  \"type\":\"long\"" +
                    "               }," +
                    "              \"last\":{" +
                    "                   \"type\":\"text\"," +
                    "                   \"fields\":{" +
                    "                      \"keyword\":{" +
                    "                           \"type\":\"keyword\"," +
                    "                           \"ignore_above\":256" +
                    "                       }" +
                "                       }" +
                "                     }" +
                    "           }" +
                    "           }" +
                    "}";

            createIndex(indexName, Settings.EMPTY, indexMappingJSON);

            Map<String, Object> mappings = getIndexMappingsAPI(indexName);

            MappingsTraverser mappingsTraverser;

            mappingsTraverser = new MappingsTraverser(mappings, Set.of());

            // Copy specific paths from mappings
            Map<String, Object> filteredMappings = mappingsTraverser.traverseAndCopyWithFilter(
                    Set.of("netflow.event_data.SourceAddress", "netflow.event.stop", "plain1", "user.first", "user.last")
            );

            // Now traverse filtered mapppings to confirm only copied paths are present
            List<String> paths = new ArrayList<>();
            mappingsTraverser = new MappingsTraverser(filteredMappings, Set.of());
            mappingsTraverser.addListener(new MappingsTraverser.MappingsTraverserListener() {
                @Override
                public void onLeafVisited(MappingsTraverser.Node node) {
                    paths.add(node.currentPath);
                }

                @Override
                public void onError(String error) {
                    fail("Failed traversing valid mappings");
                }
            });
            mappingsTraverser.traverse();
            assertEquals(5, paths.size());
            assertTrue(paths.contains("user.first"));
            assertTrue(paths.contains("user.last"));
            assertTrue(paths.contains("plain1"));
            assertTrue(paths.contains("netflow.event.stop"));
            assertTrue(paths.contains("netflow.event_data.SourceAddress"));

        } catch (IOException e) {
            fail("Error instantiating MappingsTraverser with JSON string as mappings");
        }
    }

    public void testAzureMappings() throws IOException {

        String indexName = "azure-test-index";
        String sampleDoc = readResource("azure-sample.json");

        createIndex(indexName, Settings.EMPTY);

        indexDoc(indexName, "1", sampleDoc);

        createMappingsAPI(indexName, Detector.DetectorType.AZURE.getDetectorType());

        //Expect only "timestamp" alias to be applied
        Map<String, Object> mappings = getIndexMappingsSAFlat(indexName);
        assertTrue(mappings.containsKey("timestamp"));

        // Verify that all rules are working
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of(indexName), List.of(),
                getPrePackagedRules(Detector.DetectorType.AZURE.getDetectorType()).stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input), Detector.DetectorType.AZURE);
        createDetector(detector);

        String request = "{\n" +
                "   \"size\": 1000,  " +
                "   \"query\" : {\n" +
                "     \"match_all\":{}\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(".opensearch-sap-azure-detectors-queries-000001", request);
        Assert.assertEquals(60, hits.size());
    }

    public void testADLDAPMappings() throws IOException {

        String indexName = "adldap-test-index";
        String sampleDoc = readResource("ad_ldap-sample.json");

        createIndex(indexName, Settings.EMPTY);

        indexDoc(indexName, "1", sampleDoc);

        createMappingsAPI(indexName, Detector.DetectorType.AD_LDAP.getDetectorType());

        //Expect only "timestamp" alias to be applied
        Map<String, Object> mappings = getIndexMappingsSAFlat(indexName);
        assertTrue(mappings.containsKey("timestamp"));

        // Verify that all rules are working
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of(indexName), List.of(),
                getPrePackagedRules(Detector.DetectorType.AD_LDAP.getDetectorType()).stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input), Detector.DetectorType.AD_LDAP);
        createDetector(detector);

        String request = "{\n" +
                "   \"size\": 1000,  " +
                "   \"query\" : {\n" +
                "     \"match_all\":{}\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(".opensearch-sap-ad_ldap-detectors-queries-000001", request);
        Assert.assertEquals(11, hits.size());
    }

    public void testCloudtrailMappings() throws IOException {

        String indexName = "cloudtrail-test-index";
        String sampleDoc = readResource("cloudtrail-sample.json");

        createIndex(indexName, Settings.EMPTY);

        indexDoc(indexName, "1", sampleDoc);

        createMappingsAPI(indexName, Detector.DetectorType.CLOUDTRAIL.getDetectorType());

        //Expect only "timestamp" alias to be applied
        Map<String, Object> mappings = getIndexMappingsSAFlat(indexName);
        assertTrue(mappings.containsKey("timestamp"));

        // Verify that all rules are working
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of(indexName), List.of(),
                getPrePackagedRules(Detector.DetectorType.CLOUDTRAIL.getDetectorType()).stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input), Detector.DetectorType.CLOUDTRAIL);
        createDetector(detector);

        String request = "{\n" +
                "   \"size\": 1000,  " +
                "   \"query\" : {\n" +
                "     \"match_all\":{}\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(".opensearch-sap-cloudtrail-detectors-queries-000001", request);
        Assert.assertEquals(31, hits.size());
    }

    public void testS3Mappings() throws IOException {

        String indexName = "s3-test-index";
        String sampleDoc = readResource("s3-sample.json");

        createIndex(indexName, Settings.EMPTY);

        indexDoc(indexName, "1", sampleDoc);

        createMappingsAPI(indexName, Detector.DetectorType.S3.getDetectorType());

        //Expect only "timestamp" alias to be applied
        Map<String, Object> mappings = getIndexMappingsSAFlat(indexName);
        assertTrue(mappings.containsKey("timestamp"));
        assertTrue(mappings.containsKey("Requester"));

        // Verify that all rules are working
        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of(indexName), List.of(),
                getPrePackagedRules(Detector.DetectorType.S3.getDetectorType()).stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input), Detector.DetectorType.S3);
        createDetector(detector);

        String request = "{\n" +
                "   \"size\": 1000,  " +
                "   \"query\" : {\n" +
                "     \"match_all\":{}\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(".opensearch-sap-s3-detectors-queries-000001", request);
        Assert.assertEquals(1, hits.size());
    }
}
