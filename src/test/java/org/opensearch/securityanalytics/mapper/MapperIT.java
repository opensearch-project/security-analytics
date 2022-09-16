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
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.action.CreateIndexMappingsRequest;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.opensearch.securityanalytics.TestHelpers.*;

public class MapperIT extends SecurityAnalyticsRestTestCase {

    public void testCreateMappingSuccess() throws IOException {

        String testIndexName = "my_index";
        createTestIndex(testIndexName, netFlowMappings());
        indexDoc(testIndexName, "1", randomNetFlowDoc());

        CreateIndexMappingsRequest request = new CreateIndexMappingsRequest(testIndexName, "netflow");

        // Execute CreateMappingsAction to add alias mapping for index
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI, Collections.emptyMap(), toHttpEntity(request));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Verify mappings
        GetMappingsResponse getMappingsResponse = executeGetMappingsRequest(testIndexName);
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
        SearchResponse searchResponse = executeSearchRequest(testIndexName, query);
        assertEquals(1L, searchResponse.getHits().getTotalHits().value);
    }

    public void testUpdateAndGetMappingSuccess() throws IOException {

        String testIndexName = "my_index";
        createTestIndex(testIndexName, netFlowMappings());
        indexDoc(testIndexName, "1", randomNetFlowDoc());

        UpdateIndexMappingsRequest request = new UpdateIndexMappingsRequest(testIndexName, "netflow.event_data.SourcePort", "srcport");

        // Execute UpdateMappingsAction to add alias mapping for index
        Response response = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.MAPPER_BASE_URI, Collections.emptyMap(), toHttpEntity(request));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Execute GetIndexMappingsAction and verify mappings
        Request getRequest = new Request("GET", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        getRequest.addParameter("index_name", testIndexName);
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
        SearchResponse searchResponse = executeSearchRequest(testIndexName, query);
        assertEquals(1L, searchResponse.getHits().getTotalHits().value);
    }

    public void testExistingMappingsAreUntouched() throws IOException {
        String testIndexName = "existing_mappings_ok";
        createTestIndex(testIndexName, netFlowMappings());
        indexDoc(testIndexName, "1", randomNetFlowDoc());

        CreateIndexMappingsRequest request = new CreateIndexMappingsRequest(testIndexName, "netflow");
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI, Collections.emptyMap(), toHttpEntity(request));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Verify mappings
        GetMappingsResponse getMappingsResponse = executeGetMappingsRequest(testIndexName);
        Map<String, Object> properties =
                (Map<String, Object>) getMappingsResponse.getMappings().get(testIndexName)
                .getSourceAsMap().get("properties");
        // Verify that there is still mapping for integer field "plain1"
        assertTrue(((Map<String, Object>)properties.get("plain1")).get("type").equals("integer"));
    }

    public void testMappingMissingForAliasPath() throws IOException {

        String testIndexName = "my_index_alias_fail_1";

        createIndex(testIndexName, Settings.EMPTY);

        CreateIndexMappingsRequest request = new CreateIndexMappingsRequest(testIndexName, "netflow");
        // Execute UpdateMappingsAction to add alias mapping for index
        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI, Collections.emptyMap(), toHttpEntity(request));
        } catch (ResponseException e) {
            assertTrue(e.getMessage().contains("Not all paths were found in index mappings:"));
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
}
