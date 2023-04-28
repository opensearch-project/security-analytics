/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics;

import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.cluster.ClusterModule;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.apache.hc.core5.http.HttpStatus.SC_OK;
import static org.opensearch.action.admin.indices.create.CreateIndexRequest.MAPPINGS;

public class SecurityAnalyticsClientUtils extends OpenSearchRestTestCase {


    public static GetMappingsResponse executeGetMappingsRequest(String indexName) throws IOException {

        Request getMappingsRequest = new Request("GET", indexName + "/_mapping");
        Response response = client().performRequest(getMappingsRequest);

        XContentParser parser = JsonXContent.jsonXContent.createParser(
                new NamedXContentRegistry(ClusterModule.getNamedXWriteables()),
                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                response.getEntity().getContent()
        );
        if (parser.currentToken() == null) {
            parser.nextToken();
        }

        XContentParserUtils.ensureExpectedToken(parser.currentToken(), XContentParser.Token.START_OBJECT, parser);

        Map<String, Object> parts = parser.map();

        Map<String, MappingMetadata> mappings = new HashMap<>();
        for (Map.Entry<String, Object> entry : parts.entrySet()) {
            String _indexName = entry.getKey();
            assert entry.getValue() instanceof Map : "expected a map as type mapping, but got: " + entry.getValue().getClass();

            @SuppressWarnings("unchecked") final Map<String, Object> fieldMappings = (Map<String, Object>) ((Map<String, ?>) entry.getValue()).get(
                    MAPPINGS.getPreferredName()
            );

            mappings.put(_indexName, new MappingMetadata(MapperService.SINGLE_MAPPING_NAME, fieldMappings));
        }
        Map<String, MappingMetadata> mappingsMap =  new HashMap<>(mappings);
        return new GetMappingsResponse(mappingsMap);
    }

    public static boolean executePutMappingRequest(String indexName, String mappings) throws IOException {
        Request putMappingsRequest = new Request("PUT", indexName + "/_mapping");
        Response response = client().performRequest(putMappingsRequest);
        assertEquals(SC_OK, response.getStatusLine().getStatusCode());

        XContentParser parser = JsonXContent.jsonXContent.createParser(
                new NamedXContentRegistry(ClusterModule.getNamedXWriteables()),
                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                response.getEntity().getContent()
        );
        Map<String, Object> ackResponse = parser.map();
        return (boolean) ackResponse.get("acknowledged");
    }

    public static SearchResponse executeSearchRequest(String indexName, String queryJson) throws IOException {

        Request request = new Request("GET", indexName + "/_search");
        request.setJsonEntity(queryJson);
        Response response = client().performRequest(request);

        XContentParser parser = JsonXContent.jsonXContent.createParser(
                new NamedXContentRegistry(ClusterModule.getNamedXWriteables()),
                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                response.getEntity().getContent()
        );
        return SearchResponse.fromXContent(parser);
    }

}