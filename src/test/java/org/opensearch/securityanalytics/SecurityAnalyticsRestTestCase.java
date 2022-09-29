/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.junit.Assert;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.client.WarningsHandler;
import org.opensearch.cluster.ClusterModule;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.collect.ImmutableOpenMap;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.DeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.commons.alerting.util.IndexUtilsKt;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.action.CreateIndexMappingsRequest;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsRequest;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.opensearch.action.admin.indices.create.CreateIndexRequest.MAPPINGS;

public class SecurityAnalyticsRestTestCase extends OpenSearchRestTestCase {

    protected String createTestIndex(String index, String mapping) throws IOException {
        createTestIndex(index, mapping, Settings.EMPTY);
        return index;
    }

    protected String createTestIndex(String index, String mapping, Settings settings) throws IOException {
        createIndex(index, settings, mapping);
        return index;
    }

    protected Response makeRequest(RestClient client, String method, String endpoint, Map<String, String> params,
                                   HttpEntity entity, Header... headers) throws IOException {
        Request request = new Request(method, endpoint);
        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        options.setWarningsHandler(WarningsHandler.PERMISSIVE);

        for (Header header: headers) {
            options.addHeader(header.getName(), header.getValue());
        }
        request.setOptions(options.build());
        request.addParameters(params);
        if (entity != null) {
            request.setEntity(entity);
        }
        return client.performRequest(request);
    }

    protected Boolean doesIndexExist(String index) throws IOException {
        Response response = makeRequest(client(), "HEAD", String.format(Locale.getDefault(), "/%s", index), Collections.emptyMap(), null);
        return RestStatus.OK.equals(restStatus(response));
    }

    protected Response executeAlertingMonitor(String monitorId, Map<String, String> params) throws IOException {
        return executeAlertingMonitor(client(), monitorId, params);
    }

    protected Response executeAlertingMonitor(RestClient client, String monitorId, Map<String, String> params) throws IOException {
        return makeRequest(client, "POST", String.format(Locale.getDefault(), "/_plugins/_alerting/monitors/%s/_execute", monitorId), params, null);
    }

    protected List<SearchHit> executeSearch(String index, String request) throws IOException {
        return executeSearch(index, request, true);
    }

    protected List<SearchHit> executeSearch(String index, String request, Boolean refresh) throws IOException {
        if (refresh) {
            refreshIndex(index);
        }

        Response response = makeRequest(client(), "GET", String.format(Locale.getDefault(), "%s/_search", index), Collections.emptyMap(), new StringEntity(request), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Search failed", RestStatus.OK, restStatus(response));

        SearchResponse searchResponse = SearchResponse.fromXContent(createParser(JsonXContent.jsonXContent, response.getEntity().getContent()));
        return Arrays.asList(searchResponse.getHits().getHits());
    }

    protected SearchResponse executeSearchAndGetResponse(String index, String request, Boolean refresh) throws IOException {
        if (refresh) {
            refreshIndex(index);
        }

        Response response = makeRequest(client(), "GET", String.format(Locale.getDefault(), "%s/_search", index), Collections.emptyMap(), new StringEntity(request), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Search failed", RestStatus.OK, restStatus(response));

        return SearchResponse.fromXContent(createParser(JsonXContent.jsonXContent, response.getEntity().getContent()));
    }

    protected boolean alertingMonitorExists(String monitorId) throws IOException {
        return alertingMonitorExists(client(), monitorId);
    }

    protected boolean alertingMonitorExists(RestClient client, String monitorId) throws IOException {
        try {
            Response response = makeRequest(client, "GET", String.format(Locale.getDefault(), "/_plugins/_alerting/monitors/%s", monitorId), Collections.emptyMap(), null);
            return response.getStatusLine().getStatusCode() == 200 && asMap(response).get("_id").toString().equals(monitorId);
        } catch (ResponseException ex) {
            return ex.getResponse().getStatusLine().getStatusCode() != 404;
        }
    }

    protected Response refreshIndex(String index) throws IOException {
        Response response = makeRequest(client(), "POST", String.format(Locale.getDefault(), "%s/_refresh", index), Collections.emptyMap(), null);
        Assert.assertEquals("Unable to refresh index", RestStatus.OK, restStatus(response));
        return response;
    }

    protected Response indexDoc(String index, String id, String doc) throws IOException {
        return indexDoc(client(), index, id, doc, true);
    }

    protected Response indexDoc(RestClient client, String index, String id, String doc, Boolean refresh) throws IOException {
        StringEntity requestBody = new StringEntity(doc, ContentType.APPLICATION_JSON);
        Map<String, String> params = refresh? Map.of("refresh", "true"): Collections.emptyMap();
        Response response = makeRequest(client, "PUT", String.format(Locale.getDefault(), "%s/_doc/%s", index, id), params, requestBody);

        Assert.assertTrue(String.format(Locale.getDefault(), "Unable to index doc: '%s...' to index: '%s'", doc.substring(0, 15), index), List.of(RestStatus.OK, RestStatus.CREATED).contains(restStatus(response)));
        return response;
    }

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
        ImmutableOpenMap<String, MappingMetadata> immutableMappingsMap =
                new ImmutableOpenMap.Builder<String, MappingMetadata>().putAll(mappings).build();
        return new GetMappingsResponse(immutableMappingsMap);
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

    protected HttpEntity toHttpEntity(Detector detector) throws IOException {
        return new StringEntity(toJsonString(detector), ContentType.APPLICATION_JSON);
    }

    protected HttpEntity toHttpEntity(Rule rule) throws IOException {
        return new StringEntity(toJsonString(rule), ContentType.APPLICATION_JSON);
    }

    protected HttpEntity toHttpEntity(CreateIndexMappingsRequest request) throws IOException {
        return new StringEntity(toJsonString(request), ContentType.APPLICATION_JSON);
    }

    protected HttpEntity toHttpEntity(UpdateIndexMappingsRequest request) throws IOException {
        return new StringEntity(toJsonString(request), ContentType.APPLICATION_JSON);
    }

    protected RestStatus restStatus(Response response) {
        return RestStatus.fromCode(response.getStatusLine().getStatusCode());
    }

    protected Map<String, Object> asMap(Response response) throws IOException {
        return entityAsMap(response);
    }

    private String toJsonString(Detector detector) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(detector.toXContent(builder, ToXContent.EMPTY_PARAMS)));
    }

    private String toJsonString(Rule rule) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(rule.toXContent(builder, ToXContent.EMPTY_PARAMS)));
    }

    private String toJsonString(CreateIndexMappingsRequest request) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(request.toXContent(builder, ToXContent.EMPTY_PARAMS)));
    }

    private String toJsonString(UpdateIndexMappingsRequest request) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(request.toXContent(builder, ToXContent.EMPTY_PARAMS)));
    }
}