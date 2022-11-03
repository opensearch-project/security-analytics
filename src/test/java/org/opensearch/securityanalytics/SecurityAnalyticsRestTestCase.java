/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import java.io.File;
import java.nio.file.Path;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
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
import org.opensearch.common.UUIDs;
import org.opensearch.common.collect.ImmutableOpenMap;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.DeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.commons.alerting.model.ScheduledJob;
import org.opensearch.commons.alerting.util.IndexUtilsKt;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.action.CreateIndexMappingsRequest;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsRequest;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import static org.opensearch.action.admin.indices.create.CreateIndexRequest.MAPPINGS;
import static org.opensearch.securityanalytics.util.RuleTopicIndices.ruleTopicIndexMappings;
import static org.opensearch.securityanalytics.util.RuleTopicIndices.ruleTopicIndexSettings;

public class SecurityAnalyticsRestTestCase extends OpenSearchRestTestCase {

    protected void createRuleTopicIndex(String detectorType, String additionalMapping) throws IOException {

        String mappings = "" +
                "  \"_meta\": {" +
                "    \"schema_version\": 1" +
                "  }," +
                "  \"properties\": {" +
                "    \"query\": {" +
                "      \"type\": \"percolator_ext\"" +
                "    }," +
                "    \"monitor_id\": {" +
                "      \"type\": \"text\"" +
                "    }," +
                "    \"index\": {" +
                "      \"type\": \"text\"" +
                "    }" +
                "  }";

        String indexName = DetectorMonitorConfig.getRuleIndex(detectorType);
        createIndex(
                indexName,
                Settings.builder().loadFromSource(ruleTopicIndexSettings(), XContentType.JSON).build(),
                mappings
        );
        // Update mappings
        if (additionalMapping != null) {
            Response response = makeRequest(client(), "PUT", indexName + "/_mapping", Collections.emptyMap(), new StringEntity(additionalMapping), new BasicHeader("Content-Type", "application/json"));
            assertEquals(RestStatus.OK, restStatus(response));
        }
    }

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

    protected String createDestination() throws IOException {
        String id = UUIDs.base64UUID();
        String randomDestination = "{\"destination\":{\"id\":\"\",\"test_action\":\"dummy\",\"seq_no\":0,\"primary_term\":0,\"type\":\"test_action\",\"schema_version\":0,\"name\":\"test\",\"last_update_time\":" + System.currentTimeMillis() + "}}";

        Response response = indexDocWithAdminClient(ScheduledJob.SCHEDULED_JOBS_INDEX, id, randomDestination);
        Map<String, Object> responseMap = entityAsMap(response);
        return responseMap.get("_id").toString();
    }

    protected void createAlertingMonitorConfigIndex(String mapping) throws IOException {
        if (!doesIndexExist(ScheduledJob.SCHEDULED_JOBS_INDEX)) {
            String mappingHack = mapping == null? alertingScheduledJobMappings(): mapping;
            Settings settings = Settings.builder().put("index.hidden", true).build();
            createTestIndex(ScheduledJob.SCHEDULED_JOBS_INDEX, mappingHack, settings);
        }
    }

    protected Response refreshIndex(String index) throws IOException {
        Response response = makeRequest(client(), "POST", String.format(Locale.getDefault(), "%s/_refresh", index), Collections.emptyMap(), null);
        Assert.assertEquals("Unable to refresh index", RestStatus.OK, restStatus(response));
        return response;
    }

    @SuppressWarnings("unchecked")
    protected List<String> getRandomPrePackagedRules() throws IOException {
        String request = "{\n" +
                "  \"from\": 0\n," +
                "  \"size\": 2000\n," +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"rule\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"rule.category\": \"windows\"}}\n" +
                "          ]\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";

        Response searchResponse = makeRequest(client(), "POST", String.format(Locale.getDefault(), "%s/_search", SecurityAnalyticsPlugin.RULE_BASE_URI), Collections.singletonMap("pre_packaged", "true"),
                new StringEntity(request), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Searching rules failed", RestStatus.OK, restStatus(searchResponse));

        Map<String, Object> responseBody = asMap(searchResponse);
        List<Map<String, Object>> hits = ((List<Map<String, Object>>) ((Map<String, Object>) responseBody.get("hits")).get("hits"));
        return hits.stream().map(hit -> hit.get("_id").toString()).collect(Collectors.toList());
    }

    protected List<String> getPrePackagedRules(String ruleCategory) throws IOException {
        String request = "{\n" +
                "  \"from\": 0\n," +
                "  \"size\": 2000\n," +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"rule\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"rule.category\": \"" + ruleCategory + "\"}}\n" +
                "          ]\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";

        Response searchResponse = makeRequest(client(), "POST", String.format(Locale.getDefault(), "%s/_search", SecurityAnalyticsPlugin.RULE_BASE_URI), Collections.singletonMap("pre_packaged", "true"),
                new StringEntity(request), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Searching rules failed", RestStatus.OK, restStatus(searchResponse));

        Map<String, Object> responseBody = asMap(searchResponse);
        List<Map<String, Object>> hits = ((List<Map<String, Object>>) ((Map<String, Object>) responseBody.get("hits")).get("hits"));
        return hits.stream().map(hit -> hit.get("_id").toString()).collect(Collectors.toList());
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

    protected Response indexDocWithAdminClient(String index, String id, String doc) throws IOException {
        return indexDoc(adminClient(), index, id, doc, true);
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

    public Response searchAlertingFindings(Map<String, String> params) throws IOException {
        String baseEndpoint = "/_plugins/_alerting/findings/_search";
        if (params.size() > 0) {
            baseEndpoint += "?";
        }

        for (Map.Entry<String, String> param: params.entrySet()) {
            baseEndpoint += String.format(Locale.getDefault(), "%s=%s&", param.getKey(), param.getValue());
        }

        Response response = makeRequest(client(), "GET", baseEndpoint, params, null);
        Assert.assertEquals("Unable to retrieve findings", RestStatus.OK, restStatus(response));
        return response;
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

    private String alertingScheduledJobMappings() {
        return "  \"_meta\" : {\n" +
                "    \"schema_version\": 5\n" +
                "  },\n" +
                "  \"properties\": {\n" +
                "    \"monitor\": {\n" +
                "      \"dynamic\": \"false\",\n" +
                "      \"properties\": {\n" +
                "        \"schema_version\": {\n" +
                "          \"type\": \"integer\"\n" +
                "        },\n" +
                "        \"name\": {\n" +
                "          \"type\": \"text\",\n" +
                "          \"fields\": {\n" +
                "            \"keyword\": {\n" +
                "              \"type\": \"keyword\",\n" +
                "              \"ignore_above\": 256\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"monitor_type\": {\n" +
                "          \"type\": \"keyword\"\n" +
                "        },\n" +
                "        \"user\": {\n" +
                "          \"properties\": {\n" +
                "            \"name\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"backend_roles\": {\n" +
                "              \"type\" : \"text\",\n" +
                "              \"fields\" : {\n" +
                "                \"keyword\" : {\n" +
                "                  \"type\" : \"keyword\"\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"roles\": {\n" +
                "              \"type\" : \"text\",\n" +
                "              \"fields\" : {\n" +
                "                \"keyword\" : {\n" +
                "                  \"type\" : \"keyword\"\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"custom_attribute_names\": {\n" +
                "              \"type\" : \"text\",\n" +
                "              \"fields\" : {\n" +
                "                \"keyword\" : {\n" +
                "                  \"type\" : \"keyword\"\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"type\": {\n" +
                "          \"type\": \"keyword\"\n" +
                "        },\n" +
                "        \"enabled\": {\n" +
                "          \"type\": \"boolean\"\n" +
                "        },\n" +
                "        \"enabled_time\": {\n" +
                "          \"type\": \"date\",\n" +
                "          \"format\": \"strict_date_time||epoch_millis\"\n" +
                "        },\n" +
                "        \"last_update_time\": {\n" +
                "          \"type\": \"date\",\n" +
                "          \"format\": \"strict_date_time||epoch_millis\"\n" +
                "        },\n" +
                "        \"schedule\": {\n" +
                "          \"properties\": {\n" +
                "            \"period\": {\n" +
                "              \"properties\": {\n" +
                "                \"interval\": {\n" +
                "                  \"type\": \"integer\"\n" +
                "                },\n" +
                "                \"unit\": {\n" +
                "                  \"type\": \"keyword\"\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"cron\": {\n" +
                "              \"properties\": {\n" +
                "                \"expression\": {\n" +
                "                  \"type\": \"text\"\n" +
                "                },\n" +
                "                \"timezone\": {\n" +
                "                  \"type\": \"keyword\"\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"inputs\": {\n" +
                "          \"type\": \"nested\",\n" +
                "          \"properties\": {\n" +
                "            \"search\": {\n" +
                "              \"properties\": {\n" +
                "                \"indices\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                },\n" +
                "                \"query\": {\n" +
                "                  \"type\": \"object\",\n" +
                "                  \"enabled\": false\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"data_sources\": {\n" +
                "          \"properties\": {\n" +
                "            \"alerts_index\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"findings_index\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"query_index\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"query_index_mapping\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"group_by_fields\": {\n" +
                "          \"type\": \"text\",\n" +
                "          \"fields\": {\n" +
                "            \"keyword\": {\n" +
                "              \"type\": \"keyword\",\n" +
                "              \"ignore_above\": 256\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"triggers\": {\n" +
                "          \"type\": \"nested\",\n" +
                "          \"properties\": {\n" +
                "            \"name\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"min_time_between_executions\": {\n" +
                "              \"type\": \"integer\"\n" +
                "            },\n" +
                "            \"condition\": {\n" +
                "              \"type\": \"object\",\n" +
                "              \"enabled\": false\n" +
                "            },\n" +
                "            \"actions\": {\n" +
                "              \"type\": \"nested\",\n" +
                "              \"properties\": {\n" +
                "                \"name\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                },\n" +
                "                \"destination_id\": {\n" +
                "                  \"type\": \"keyword\"\n" +
                "                },\n" +
                "                \"subject_template\": {\n" +
                "                  \"type\": \"object\",\n" +
                "                  \"enabled\": false\n" +
                "                },\n" +
                "                \"message_template\": {\n" +
                "                  \"type\": \"object\",\n" +
                "                  \"enabled\": false\n" +
                "                },\n" +
                "                \"throttle_enabled\": {\n" +
                "                  \"type\": \"boolean\"\n" +
                "                },\n" +
                "                \"throttle\": {\n" +
                "                  \"properties\": {\n" +
                "                    \"value\": {\n" +
                "                      \"type\": \"integer\"\n" +
                "                    },\n" +
                "                    \"unit\": {\n" +
                "                      \"type\": \"keyword\"\n" +
                "                    }\n" +
                "                  }\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"query_level_trigger\": {\n" +
                "              \"properties\": {\n" +
                "                \"name\": {\n" +
                "                  \"type\": \"text\",\n" +
                "                  \"fields\": {\n" +
                "                    \"keyword\": {\n" +
                "                      \"type\": \"keyword\",\n" +
                "                      \"ignore_above\": 256\n" +
                "                    }\n" +
                "                  }\n" +
                "                },\n" +
                "                \"min_time_between_executions\": {\n" +
                "                  \"type\": \"integer\"\n" +
                "                },\n" +
                "                \"condition\": {\n" +
                "                  \"type\": \"object\",\n" +
                "                  \"enabled\": false\n" +
                "                },\n" +
                "                \"actions\": {\n" +
                "                  \"type\": \"nested\",\n" +
                "                  \"properties\": {\n" +
                "                    \"name\": {\n" +
                "                      \"type\": \"text\",\n" +
                "                      \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                          \"type\": \"keyword\",\n" +
                "                          \"ignore_above\": 256\n" +
                "                        }\n" +
                "                      }\n" +
                "                    },\n" +
                "                    \"destination_id\": {\n" +
                "                      \"type\": \"keyword\"\n" +
                "                    },\n" +
                "                    \"subject_template\": {\n" +
                "                      \"type\": \"object\",\n" +
                "                      \"enabled\": false\n" +
                "                    },\n" +
                "                    \"message_template\": {\n" +
                "                      \"type\": \"object\",\n" +
                "                      \"enabled\": false\n" +
                "                    },\n" +
                "                    \"throttle_enabled\": {\n" +
                "                      \"type\": \"boolean\"\n" +
                "                    },\n" +
                "                    \"throttle\": {\n" +
                "                      \"properties\": {\n" +
                "                        \"value\": {\n" +
                "                          \"type\": \"integer\"\n" +
                "                        },\n" +
                "                        \"unit\": {\n" +
                "                          \"type\": \"keyword\"\n" +
                "                        }\n" +
                "                      }\n" +
                "                    }\n" +
                "                  }\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"ui_metadata\": {\n" +
                "          \"type\": \"object\",\n" +
                "          \"enabled\": false\n" +
                "        }\n" +
                "      }\n" +
                "    },\n" +
                "    \"destination\": {\n" +
                "      \"dynamic\": \"false\",\n" +
                "      \"properties\": {\n" +
                "        \"schema_version\": {\n" +
                "          \"type\": \"integer\"\n" +
                "        },\n" +
                "        \"name\": {\n" +
                "          \"type\": \"text\",\n" +
                "          \"fields\": {\n" +
                "            \"keyword\": {\n" +
                "              \"type\": \"keyword\",\n" +
                "              \"ignore_above\": 256\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"user\": {\n" +
                "          \"properties\": {\n" +
                "            \"name\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"backend_roles\": {\n" +
                "              \"type\" : \"text\",\n" +
                "              \"fields\" : {\n" +
                "                \"keyword\" : {\n" +
                "                  \"type\" : \"keyword\"\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"roles\": {\n" +
                "              \"type\" : \"text\",\n" +
                "              \"fields\" : {\n" +
                "                \"keyword\" : {\n" +
                "                  \"type\" : \"keyword\"\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"custom_attribute_names\": {\n" +
                "              \"type\" : \"text\",\n" +
                "              \"fields\" : {\n" +
                "                \"keyword\" : {\n" +
                "                  \"type\" : \"keyword\"\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"type\": {\n" +
                "          \"type\": \"keyword\"\n" +
                "        },\n" +
                "        \"last_update_time\": {\n" +
                "          \"type\": \"date\",\n" +
                "          \"format\": \"strict_date_time||epoch_millis\"\n" +
                "        },\n" +
                "        \"chime\": {\n" +
                "          \"properties\": {\n" +
                "            \"url\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"slack\": {\n" +
                "          \"properties\": {\n" +
                "            \"url\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"custom_webhook\": {\n" +
                "          \"properties\": {\n" +
                "            \"url\": {\n" +
                "              \"type\": \"text\",\n" +
                "              \"fields\": {\n" +
                "                \"keyword\": {\n" +
                "                  \"type\": \"keyword\",\n" +
                "                  \"ignore_above\": 256\n" +
                "                }\n" +
                "              }\n" +
                "            },\n" +
                "            \"scheme\": {\n" +
                "              \"type\": \"keyword\"\n" +
                "            },\n" +
                "            \"host\": {\n" +
                "              \"type\": \"text\"\n" +
                "            },\n" +
                "            \"port\": {\n" +
                "              \"type\": \"integer\"\n" +
                "            },\n" +
                "            \"path\": {\n" +
                "              \"type\": \"keyword\"\n" +
                "            },\n" +
                "            \"query_params\": {\n" +
                "              \"type\": \"object\",\n" +
                "              \"enabled\": false\n" +
                "            },\n" +
                "            \"header_params\": {\n" +
                "              \"type\": \"object\",\n" +
                "              \"enabled\": false\n" +
                "            },\n" +
                "            \"username\": {\n" +
                "              \"type\": \"text\"\n" +
                "            },\n" +
                "            \"password\": {\n" +
                "              \"type\": \"text\"\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"email\": {\n" +
                "          \"properties\": {\n" +
                "            \"email_account_id\": {\n" +
                "              \"type\": \"keyword\"\n" +
                "            },\n" +
                "            \"recipients\": {\n" +
                "              \"type\": \"nested\",\n" +
                "              \"properties\": {\n" +
                "                \"type\": {\n" +
                "                  \"type\": \"keyword\"\n" +
                "                },\n" +
                "                \"email_group_id\": {\n" +
                "                  \"type\": \"keyword\"\n" +
                "                },\n" +
                "                \"email\": {\n" +
                "                  \"type\": \"text\"\n" +
                "                }\n" +
                "              }\n" +
                "            }\n" +
                "          }\n" +
                "        }\n" +
                "      }\n" +
                "    },\n" +
                "    \"email_account\": {\n" +
                "      \"properties\": {\n" +
                "        \"name\": {\n" +
                "          \"type\": \"text\",\n" +
                "          \"fields\": {\n" +
                "            \"keyword\": {\n" +
                "              \"type\": \"keyword\",\n" +
                "              \"ignore_above\": 256\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"host\": {\n" +
                "          \"type\": \"text\"\n" +
                "        },\n" +
                "        \"port\": {\n" +
                "          \"type\": \"integer\"\n" +
                "        },\n" +
                "        \"method\": {\n" +
                "          \"type\": \"text\"\n" +
                "        },\n" +
                "        \"from\": {\n" +
                "          \"type\": \"text\"\n" +
                "        }\n" +
                "      }\n" +
                "    },\n" +
                "    \"email_group\": {\n" +
                "      \"properties\": {\n" +
                "        \"name\": {\n" +
                "          \"type\": \"text\",\n" +
                "          \"fields\": {\n" +
                "            \"keyword\": {\n" +
                "              \"type\": \"keyword\",\n" +
                "              \"ignore_above\": 256\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"emails\": {\n" +
                "          \"type\": \"nested\",\n" +
                "          \"properties\": {\n" +
                "            \"email\": {\n" +
                "              \"type\": \"text\"\n" +
                "            }\n" +
                "          }\n" +
                "        }\n" +
                "      }\n" +
                "    },\n" +
                "    \"metadata\" : {\n" +
                "      \"properties\": {\n" +
                "        \"monitor_id\": {\n" +
                "          \"type\": \"keyword\"\n" +
                "        },\n" +
                "        \"last_action_execution_times\": {\n" +
                "          \"type\": \"nested\",\n" +
                "          \"properties\": {\n" +
                "            \"action_id\": {\n" +
                "              \"type\": \"keyword\"\n" +
                "            },\n" +
                "            \"execution_time\": {\n" +
                "              \"type\": \"date\",\n" +
                "              \"format\": \"strict_date_time||epoch_millis\"\n" +
                "            }\n" +
                "          }\n" +
                "        },\n" +
                "        \"last_run_context\": {\n" +
                "          \"type\": \"object\",\n" +
                "          \"enabled\": false\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }";
    }

    protected void createNetflowLogIndex(String indexName) throws IOException {
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
                        "        }" +
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