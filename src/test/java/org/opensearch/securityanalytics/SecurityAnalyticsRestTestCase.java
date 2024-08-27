/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.opensearch.action.admin.indices.mapping.get.GetMappingsResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.WarningsHandler;
import org.opensearch.cluster.ClusterModule;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.UUIDs;
import org.opensearch.common.io.PathUtils;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.commons.ConfigConstants;
import org.opensearch.commons.alerting.model.ScheduledJob;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.commons.alerting.util.IndexUtilsKt;
import org.opensearch.commons.rest.SecureRestClientBuilder;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.MediaType;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.action.AlertDto;
import org.opensearch.securityanalytics.action.CreateIndexMappingsRequest;
import org.opensearch.securityanalytics.action.TestS3ConnectionRequest;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsRequest;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.correlation.CorrelationEngineRestApiIT;
import org.opensearch.securityanalytics.correlation.index.query.CorrelationQueryBuilder;
import org.opensearch.securityanalytics.mapper.MappingsTraverser;
import org.opensearch.securityanalytics.model.CorrelationQuery;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.model.CorrelationRuleTrigger;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.model.ThreatIntelFeedData;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.IocFindingService;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import javax.management.MBeanServerInvocationHandler;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import static org.opensearch.action.admin.indices.create.CreateIndexRequest.MAPPINGS;
import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.MAPPER_BASE_URI;
import static org.opensearch.securityanalytics.TestHelpers.adLdapLogMappings;
import static org.opensearch.securityanalytics.TestHelpers.appLogMappings;
import static org.opensearch.securityanalytics.TestHelpers.productIndexAvgAggRule;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputsAndTriggers;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputsAndTriggersAndType;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.s3AccessLogMappings;
import static org.opensearch.securityanalytics.TestHelpers.sumAggregationTestRule;
import static org.opensearch.securityanalytics.TestHelpers.vpcFlowMappings;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;
import static org.opensearch.securityanalytics.services.STIX2IOCFeedStore.IOC_ALL_INDEX_PATTERN;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_INDEX_MAX_AGE;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_MAX_DOCS;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_RETENTION_PERIOD;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.ALERT_HISTORY_ROLLOVER_PERIOD;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_INDEX_MAX_AGE;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_MAX_DOCS;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_RETENTION_PERIOD;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.FINDING_HISTORY_ROLLOVER_PERIOD;
import static org.opensearch.securityanalytics.threatIntel.util.ThreatIntelFeedDataUtils.getTifdList;
import static org.opensearch.securityanalytics.util.RuleTopicIndices.ruleTopicIndexSettings;

public class SecurityAnalyticsRestTestCase extends OpenSearchRestTestCase {

    protected String password = "V%&ymu35#wbQaUo7";

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

    protected void verifyWorkflow(Map<String, Object> detectorMap, List<String> monitorIds, int expectedDelegatesNum) throws IOException {
        String workflowId = ((List<String>) detectorMap.get("workflow_ids")).get(0);

        Map<String, Object> workflow = searchWorkflow(workflowId);
        assertNotNull("Workflow not found", workflow);

        List<Map<String, Object>> workflowInputs = (List<Map<String, Object>>) workflow.get("inputs");
        assertEquals("Workflow not found", 1, workflowInputs.size());

        Map<String, Object> sequence = ((Map<String, Object>) ((Map<String, Object>) workflowInputs.get(0).get("composite_input")).get("sequence"));
        assertNotNull("Sequence is null", sequence);

        List<Map<String, Object>> delegates = (List<Map<String, Object>>) sequence.get("delegates");
        assertEquals(expectedDelegatesNum, delegates.size());
        // Assert that all monitors are present
        for (Map<String, Object> delegate : delegates) {
            assertTrue("Monitor doesn't exist in monitor list", monitorIds.contains(delegate.get("monitor_id")));
        }
    }

    protected Map<String, Object> searchWorkflow(String workflowId) throws IOException {
        String workflowRequest = "{\n" +
                "   \"query\":{\n" +
                "      \"term\":{\n" +
                "         \"_id\":{\n" +
                "            \"value\":\"" + workflowId + "\"\n" +
                "         }\n" +
                "      }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeWorkflowSearch("/_plugins/_alerting/monitors", workflowRequest);

        if (hits.size() == 0) {
            return new HashMap<>();
        }

        SearchHit hit = hits.get(0);
        return (Map<String, Object>) hit.getSourceAsMap();
    }


    protected List<Map<String, Object>> getAllWorkflows() throws IOException {
        String workflowRequest = "{\n" +
                "   \"query\":{\n" +
                "      \"exists\":{\n" +
                "         \"field\": \"workflow\"" +
                "         }\n" +
                "      }\n" +
                "   }";

        List<SearchHit> hits = executeSearch(ScheduledJob.SCHEDULED_JOBS_INDEX, workflowRequest);
        if (hits.size() == 0) {
            return new ArrayList<>();
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (SearchHit hit : hits) {
            result.add((Map<String, Object>) hit.getSourceAsMap().get("workflow"));
        }
        return result;
    }

    protected String createDetector(Detector detector) throws IOException {
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        return responseBody.get("_id").toString();
    }

    protected void deleteDetector(String detectorId) throws IOException {
        makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + detectorId, Collections.emptyMap(), null);
    }

    protected List<Object> getAllComponentTemplates() throws IOException {
        Response response = makeRequest(client(), "GET", "_component_template", Collections.emptyMap(), null);
        assertEquals(RestStatus.OK, restStatus(response));
        Map<String, Object> responseBody = asMap(response);
        return (List<Object>) responseBody.get("component_templates");
    }

    protected List<Object> getAllComposableIndexTemplates() throws IOException {
        Response response = makeRequest(client(), "GET", "_index_template", Collections.emptyMap(), null);
        assertEquals(RestStatus.OK, restStatus(response));
        Map<String, Object> responseBody = asMap(response);
        return (List<Object>) responseBody.get("index_templates");
    }

    @SuppressWarnings("unchecked")
    protected List<Map<String, Object>> searchCorrelatedFindings(String findingId, String detectorType, long timeWindow, int nearestFindings) throws IOException {
        Response response = makeRequest(client(), "GET", "/_plugins/_security_analytics/findings/correlate", Map.of("finding", findingId, "detector_type", detectorType,
                        "time_window", String.valueOf(timeWindow), "nearby_findings", String.valueOf(nearestFindings)),
                null, new BasicHeader("Content-Type", "application/json"));
        return (List<Map<String, Object>>) entityAsMap(response).get("findings");
    }

    @Before
    void setDebugLogLevel() throws IOException, InterruptedException {
        StringEntity se = new StringEntity("{\n" +
                "                    \"transient\": {\n" +
                "                        \"logger.org.opensearch.securityanalytics\":\"DEBUG\",\n" +
                "                        \"logger.org.opensearch.jobscheduler\":\"DEBUG\",\n" +
                "                        \"logger.org.opensearch.alerting\":\"DEBUG\"\n" +
                "                    }\n" +
                "                }");


        makeRequest(client(), "PUT", "_cluster/settings", Collections.emptyMap(), se, new BasicHeader("Content-Type", "application/json"));
    }

    protected final List<String> clusterPermissions = List.of(
            "cluster:admin/opensearch/securityanalytics/detector/*",
            "cluster:admin/opendistro/alerting/alerts/*",
            "cluster:admin/opendistro/alerting/findings/*",
            "cluster:admin/opensearch/securityanalytics/mapping/*",
            "cluster:admin/opensearch/securityanalytics/rule/*"
    );

    protected final List<String> indexPermissions = List.of(
            "indices:admin/mappings/get",
            "indices:admin/mapping/put",
            "indices:data/read/search"
    );

    protected static String TEST_HR_ROLE = "hr_role";

    protected String createTestIndex(String index, String mapping) throws IOException {
        createTestIndex(index, mapping, Settings.EMPTY);
        return index;
    }

    protected String createTestIndex(String index, String mapping, Settings settings) throws IOException {
        createIndex(index, settings, mapping);
        return index;
    }

    protected String createTestIndex(RestClient client, String index, String mapping, Settings settings) throws IOException {
        Request request = new Request("PUT", "/" + index);
        String entity = "{\"settings\": " + Strings.toString(XContentType.JSON, settings);
        if (mapping != null) {
            entity = entity + ",\"mappings\" : {" + mapping + "}";
        }

        entity = entity + "}";
        if (!settings.getAsBoolean(IndexSettings.INDEX_SOFT_DELETES_SETTING.getKey(), true)) {
            expectSoftDeletesWarning(request, index);
        }

        request.setJsonEntity(entity);
        client.performRequest(request);
        return index;
    }

    protected String createDocumentWithNFields(int numOfFields) {
        StringBuilder doc = new StringBuilder();
        doc.append("{");
        for (int i = 0; i < numOfFields - 1; i++) {
            doc.append("\"id").append(i).append("\": 5,");
        }
        doc.append("\"last_field\": 100 }");

        return doc.toString();
    }

    protected Response makeRequest(RestClient client, String method, String endpoint, Map<String, String> params,
                                   HttpEntity entity, Header... headers) throws IOException {
        Request request = new Request(method, endpoint);
        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        options.setWarningsHandler(WarningsHandler.PERMISSIVE);

        for (Header header : headers) {
            options.addHeader(header.getName(), header.getValue());
        }
        request.setOptions(options.build());
        request.addParameters(params);
        if (entity != null) {
            request.setEntity(entity);
        }
        return client.performRequest(request);
    }

    protected Settings getCorrelationDefaultIndexSettings() {
        return Settings.builder().put("number_of_shards", 1).put("number_of_replicas", 0).put("index.correlation", true).build();
    }

    protected String createTestIndexWithMappingJson(RestClient client, String index, String mapping, Settings settings) throws IOException {
        Request request = new Request("PUT", "/" + index);
        String entity = "{\"settings\": " + Strings.toString(XContentType.JSON, settings);
        if (mapping != null) {
            entity = entity + ",\"mappings\" : " + mapping;
        }

        entity = entity + "}";
        if (!settings.getAsBoolean(IndexSettings.INDEX_SOFT_DELETES_SETTING.getKey(), true)) {
            expectSoftDeletesWarning(request, index);
        }

        request.setJsonEntity(entity);
        client.performRequest(request);
        return index;
    }

    protected void addCorrelationDoc(String index, String docId, List<String> fieldNames, List<Object> vectors) throws IOException {
        Request request = new Request("POST", "/" + index + "/_doc/" + docId + "?refresh=true");

        XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
        for (int i = 0; i < fieldNames.size(); i++) {
            builder.field(fieldNames.get(i), vectors.get(i));
        }
        builder.endObject();

        request.setJsonEntity(builder.toString());
        Response response = client().performRequest(request);
        assertEquals(request.getEndpoint() + ": failed", RestStatus.CREATED, RestStatus.fromCode(response.getStatusLine().getStatusCode()));
    }

    protected int getDocCount(String index) throws IOException {
        Response response = makeRequest(client(), "GET", String.format(Locale.getDefault(), "/%s/_count", index), Collections.emptyMap(), null);
        Assert.assertEquals(RestStatus.OK, restStatus(response));
        return Integer.parseInt(entityAsMap(response).get("count").toString());
    }

    protected Response searchCorrelationIndex(String index, CorrelationQueryBuilder correlationQueryBuilder, int resultSize) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder().startObject().startObject("query");
        correlationQueryBuilder.doXContent(builder, ToXContent.EMPTY_PARAMS);
        builder.endObject().endObject();

        Request request = new Request("POST", "/" + index + "/_search");

        request.addParameter("size", Integer.toString(resultSize));
        request.addParameter("explain", Boolean.toString(true));
        request.addParameter("search_type", "query_then_fetch");
        request.setJsonEntity(builder.toString());

        Response response = client().performRequest(request);
        Assert.assertEquals("Search failed", RestStatus.OK, restStatus(response));
        return response;
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

    protected Response deleteAlertingMonitorIndex() throws IOException {
        return makeRequest(client(), "DELETE", String.format(Locale.getDefault(), "/.opendistro-alerting-config"), new HashMap<>(), null);
    }

    protected Response deleteAlertingMonitor(String monitorId) throws IOException {
        return deleteAlertingMonitor(client(), monitorId);
    }

    protected Response deleteAlertingMonitor(RestClient client, String monitorId) throws IOException {
        return makeRequest(client, "DELETE", String.format(Locale.getDefault(), "/_plugins/_alerting/monitors/%s", monitorId), new HashMap<>(), null);
    }

    protected Response executeAlertingWorkflow(String monitorId, Map<String, String> params) throws IOException {
        return executeAlertingWorkflow(client(), monitorId, params);
    }

    protected Response executeAlertingWorkflow(RestClient client, String workflowId, Map<String, String> params) throws IOException {
        return makeRequest(client, "POST", String.format(Locale.getDefault(), "/_plugins/_alerting/workflows/%s/_execute", workflowId), params, null);
    }

    protected Response deleteAlertingWorkflow(String workflowId) throws IOException {
        return deleteAlertingWorkflow(client(), workflowId);
    }

    protected Response deleteAlertingWorkflow(RestClient client, String workflowId) throws IOException {
        return makeRequest(client, "DELETE", String.format(Locale.getDefault(), "/_plugins/_alerting/workflows/%s", workflowId), new HashMap<>(), null);
    }

    protected List<SearchHit> executeSearch(String index, String request) throws IOException {
        return executeSearch(index, request, true);
    }

    protected List<SearchHit> executeSearch(String index, String request, Boolean refresh) throws IOException {
        if (refresh) {
            refreshIndex(index);
        }

        Response response = makeRequest(client(), "GET", String.format(Locale.getDefault(), "%s/_search", index), Map.of("preference", "_primary"), new StringEntity(request), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Search failed", RestStatus.OK, restStatus(response));

        SearchResponse searchResponse = SearchResponse.fromXContent(createParser(JsonXContent.jsonXContent, response.getEntity().getContent()));
        return Arrays.asList(searchResponse.getHits().getHits());
    }

    protected List<SearchHit> executeWorkflowSearch(String url, String request) throws IOException {

        Response response = makeRequest(client(), "POST", String.format(Locale.getDefault(), "%s/_search", url), Collections.emptyMap(), new StringEntity(request), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Workflow search failed", RestStatus.OK, restStatus(response));

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

    protected Response getAlertingMonitor(RestClient client, String monitorId) throws IOException {
        Response response = makeRequest(client, "GET", String.format(Locale.getDefault(), "/_plugins/_alerting/monitors/%s", monitorId), Collections.emptyMap(), null);
        return response;
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
            String mappingHack = mapping == null ? alertingScheduledJobMappings() : mapping;
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
        return List.of(
                "36a037c4-c228-4866-b6a3-48eb292b9955",
                "c6e91a02-d771-4a6d-a700-42587e0b1095",
                "5a919691-7302-437f-8e10-1fe088afa145",
                "e5a6b256-3e47-40fc-89d2-7a477edd6915",
                "06724b9a-52fc-11ed-bdc3-0242ac120002"
        );
    }

    protected List<String> createAggregationRules() throws IOException {
        return new ArrayList<>(Arrays.asList(createRule(productIndexAvgAggRule()), createRule(sumAggregationTestRule())));
    }

    protected String createRule(String rule) throws IOException {
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "test_windows"),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));
        Map<String, Object> responseBody = asMap(createResponse);
        return responseBody.get("_id").toString();
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
        Map<String, String> params = refresh ? Map.of("refresh", "true") : Collections.emptyMap();
        Response response = makeRequest(client, "POST", String.format(Locale.getDefault(), "%s/_doc/%s?op_type=create", index, id), params, requestBody);
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
        Map<String, MappingMetadata> mappingsMap = new HashMap<>(mappings);
        return new GetMappingsResponse(mappingsMap);
    }

    public Response searchAlertingFindings(Map<String, String> params) throws IOException {
        String baseEndpoint = "/_plugins/_alerting/findings/_search";
        if (params.size() > 0) {
            baseEndpoint += "?";
        }

        for (Map.Entry<String, String> param : params.entrySet()) {
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

    public static SearchResponse executeSearchRequest(RestClient client, String indexName, String queryJson) throws IOException {

        Request request = new Request("GET", indexName + "/_search");
        request.setJsonEntity(queryJson);
        Response response = client.performRequest(request);

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

    protected HttpEntity toHttpEntity(CustomLogType logType) throws IOException {
        return new StringEntity(toJsonString(logType), ContentType.APPLICATION_JSON);
    }

    protected HttpEntity toHttpEntity(UpdateIndexMappingsRequest request) throws IOException {
        return new StringEntity(toJsonString(request), ContentType.APPLICATION_JSON);
    }

    protected HttpEntity toHttpEntity(CorrelationRule rule) throws IOException {
        return new StringEntity(toJsonString(rule), ContentType.APPLICATION_JSON);
    }

    protected HttpEntity toHttpEntity(SATIFSourceConfigDto saTifSourceConfigDto) throws IOException {
        return new StringEntity(toJsonString(saTifSourceConfigDto), ContentType.APPLICATION_JSON);
    }

    protected HttpEntity toHttpEntity(IocFinding iocFinding) throws IOException {
        return new StringEntity(toJsonString(iocFinding), ContentType.APPLICATION_JSON);
    }

    protected HttpEntity toHttpEntity(ThreatIntelMonitorDto threatIntelMonitorDto) throws IOException {
        return new StringEntity(toJsonString(threatIntelMonitorDto), ContentType.APPLICATION_JSON);
    }

    protected HttpEntity toHttpEntity(TestS3ConnectionRequest testS3ConnectionRequest) throws IOException {
        return new StringEntity(toJsonString(testS3ConnectionRequest), ContentType.APPLICATION_JSON);
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

    private String toJsonString(CustomLogType logType) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(logType.toXContent(builder, ToXContent.EMPTY_PARAMS)));
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

    protected String toJsonString(CorrelationRule rule) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(rule.toXContent(builder, ToXContent.EMPTY_PARAMS)));
    }

    protected String toJsonString(ThreatIntelFeedData tifd) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(tifd.toXContent(builder, ToXContent.EMPTY_PARAMS)));
    }

    private String toJsonString(SATIFSourceConfigDto saTifSourceConfigDto) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(saTifSourceConfigDto.toXContent(builder, ToXContent.EMPTY_PARAMS)));
    }

    private String toJsonString(ThreatIntelMonitorDto threatIntelMonitorDto) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(threatIntelMonitorDto.toXContent(builder, ToXContent.EMPTY_PARAMS)));
    }

    private String toJsonString(IocFinding iocFinding) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(iocFinding.toXContent(builder, ToXContent.EMPTY_PARAMS)));
    }

    public String toJsonString(ThreatIntelAlert alert) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(alert.toXContent(builder, ToXContent.EMPTY_PARAMS)));
    }

    private String toJsonString(TestS3ConnectionRequest testS3ConnectionRequest) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        return IndexUtilsKt.string(shuffleXContent(testS3ConnectionRequest.toXContent(builder, ToXContent.EMPTY_PARAMS)));
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

    protected boolean isHttps() {
        return Boolean.parseBoolean(System.getProperty("https", "false"));
    }

    protected boolean securityEnabled() {
        return Boolean.parseBoolean(System.getProperty("https", "false"));
    }

    @Override
    protected String getProtocol() {
        if (isHttps()) {
            return "https";
        } else {
            return "http";
        }
    }

    @Override
    protected Settings restAdminSettings() {

        return Settings
                .builder()
                .put("http.port", 9200)
                .put(ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_ENABLED, isHttps())
                .put(ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_PEMCERT_FILEPATH, "sample.pem")
                .put(ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH, "test-kirk.jks")
                .put(ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_PASSWORD, "changeit")
                .put(ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD, "changeit")
                .build();
    }


    @Override
    protected RestClient buildClient(Settings settings, HttpHost[] hosts) throws IOException {
        if (securityEnabled()) {
            String keystore = settings.get(ConfigConstants.OPENSEARCH_SECURITY_SSL_HTTP_KEYSTORE_FILEPATH);
            if (keystore != null) {
                // create adminDN (super-admin) client
                //log.info("keystore not null");
                URI uri = null;
                try {
                    uri = SecurityAnalyticsRestTestCase.class.getClassLoader().getResource("sample.pem").toURI();
                } catch (URISyntaxException e) {
                    return null;
                }
                Path configPath = PathUtils.get(uri).getParent().toAbsolutePath();
                return new SecureRestClientBuilder(settings, configPath).setSocketTimeout(60000).build();
            } else {
                // create client with passed user
                String userName = System.getProperty("user");
                String password = System.getProperty("password");
                return new SecureRestClientBuilder(hosts, isHttps(), userName, password).setSocketTimeout(60000).build();
            }
        } else {
            RestClientBuilder builder = RestClient.builder(hosts);
            configureClient(builder, settings);
            builder.setStrictDeprecationMode(true);
            return builder.build();
        }

    }

    protected void createIndexRole(String name, List<String> clusterPermissions, List<String> indexPermission, List<String> indexPatterns) throws IOException {
        Response response;
        try {
            response = client().performRequest(new Request("GET", String.format(Locale.getDefault(), "/_plugins/_security/api/roles/%s", name)));
        } catch (ResponseException ex) {
            response = ex.getResponse();
        }
        // Role already exists
        if (response.getStatusLine().getStatusCode() == RestStatus.OK.getStatus()) {
            return;
        }

        Request request = new Request("PUT", String.format(Locale.getDefault(), "/_plugins/_security/api/roles/%s", name));
        String clusterPermissionsStr = clusterPermissions.stream().map(p -> "\"" + p + "\"").collect(Collectors.joining(","));
        String indexPermissionsStr = indexPermission.stream().map(p -> "\"" + p + "\"").collect(Collectors.joining(","));
        String indexPatternsStr = indexPatterns.stream().map(p -> "\"" + p + "\"").collect(Collectors.joining(","));

        String entity = "{\n" +
                "\"cluster_permissions\": [\n" +
                "" + clusterPermissionsStr + "\n" +
                "], \n" +
                "\"index_permissions\": [\n" +
                "{" +
                "\"fls\": [], " +
                "\"masked_fields\": [], " +
                "\"allowed_actions\": [" + indexPermissionsStr + "], " +
                "\"index_patterns\": [" + indexPatternsStr + "]" +
                "}" +
                "], " +
                "\"tenant_permissions\": []" +
                "}";

        request.setJsonEntity(entity);
        client().performRequest(request);
    }

    protected void createCustomRole(String name, String clusterPermissions) throws IOException {
        Request request = new Request("PUT", String.format(Locale.getDefault(), "/_plugins/_security/api/roles/%s", name));
        String entity = "{\n" +
                "\"cluster_permissions\": [\n" +
                "\"" + clusterPermissions + "\"\n" +
                "]\n" +
                "}";
        request.setJsonEntity(entity);
        client().performRequest(request);
    }

    public void createUser(String name, String[] backendRoles) throws IOException {
        Request request = new Request("PUT", String.format(Locale.getDefault(), "/_plugins/_security/api/internalusers/%s", name));
        String broles = String.join(",", backendRoles);
        //String roles = String.join(",", customRoles);
        String entity = " {\n" +
                "\"password\": \"" + password + "\",\n" +
                "\"backend_roles\": [\"" + broles + "\"],\n" +
                "\"attributes\": {\n" +
                "}} ";
        request.setJsonEntity(entity);
        client().performRequest(request);
    }

    protected void createUserRolesMapping(String role, String[] users) throws IOException {
        Request request = new Request("PUT", String.format(Locale.getDefault(), "/_plugins/_security/api/rolesmapping/%s", role));
        String usersArr = String.join(",", users);
        String entity = "{\n" +
                "  \"backend_roles\" : [  ],\n" +
                "  \"hosts\" : [  ],\n" +
                "\"users\": [\"" + usersArr + "\"]\n" +
                "}";
        request.setJsonEntity(entity);
        client().performRequest(request);
    }

    protected void enableOrDisableFilterBy(String trueOrFalse) throws IOException {
        Request request = new Request("PUT", "_cluster/settings");
        String entity = "{\"persistent\":{\"plugins.security_analytics.filter_by_backend_roles\" : " + trueOrFalse + "}}";
        request.setJsonEntity(entity);
        client().performRequest(request);
    }

    protected void createUserWithDataAndCustomRole(String userName, String userPasswd, String roleName, String[] backendRoles, String clusterPermissions) throws IOException {
        String[] users = {userName};
        createUser(userName, backendRoles);
        createCustomRole(roleName, clusterPermissions);
        createUserRolesMapping(roleName, users);
    }

    protected void createUserWithDataAndCustomRole(String userName, String userPasswd, String roleName, String[] backendRoles, List<String> clusterPermissions, List<String> indexPermissions, List<String> indexPatterns) throws IOException {
        String[] users = {userName};
        createUser(userName, backendRoles);
        createIndexRole(roleName, clusterPermissions, indexPermissions, indexPatterns);
        createUserRolesMapping(roleName, users);
    }

    protected void createUserWithData(String userName, String userPasswd, String roleName, String[] backendRoles) throws IOException {
        String[] users = {userName};
        createUser(userName, backendRoles);
        createUserRolesMapping(roleName, users);
    }

    public void createUserWithTestData(String user, String index, String role, String[] backendRoles, List<String> indexPermissions) throws IOException {
        String[] users = {user};
        createUser(user, backendRoles);
        createTestIndex(client(), index, windowsIndexMapping(), Settings.EMPTY);
        createIndexRole(role, Collections.emptyList(), indexPermissions, List.of(index));
        createUserRolesMapping(role, users);
    }

    protected void deleteUser(String name) throws IOException {
        Request request = new Request("DELETE", String.format(Locale.getDefault(), "/_plugins/_security/api/internalusers/%s", name));
        client().performRequest(request);
    }

    protected void tryDeletingRole(String name) throws IOException {
        Response response;
        try {
            response = client().performRequest(new Request("GET", String.format(Locale.getDefault(), "/_plugins/_security/api/roles/%s", name)));
        } catch (ResponseException ex) {
            response = ex.getResponse();
        }
        // Role already exists
        if (response.getStatusLine().getStatusCode() == RestStatus.OK.getStatus()) {
            Request request = new Request("DELETE", String.format(Locale.getDefault(), "/_plugins/_security/api/roles/%s", name));
            client().performRequest(request);
        }
    }

    @Override
    protected boolean preserveIndicesUponCompletion() {
        return true;
    }

    boolean preserveODFEIndicesAfterTest() {
        return false;
    }

    @After
    protected void wipeAllODFEIndices() throws IOException {
        if (preserveODFEIndicesAfterTest()) return;

        Response response = client().performRequest(new Request("GET", "/_cat/indices?format=json&expand_wildcards=all"));

        MediaType xContentType = MediaTypeRegistry.fromMediaType(response.getEntity().getContentType());
        XContentParser parser = xContentType.xContent().createParser(
                NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                response.getEntity().getContent()
        );


        for (Object index : parser.list()) {
            Map<String, Object> jsonObject = (Map<String, Object>) index;

            String indexName = jsonObject.get("index").toString();
            // .opendistro_security isn't allowed to delete from cluster
            if (!".opendistro_security".equals(indexName)) {
                Request request = new Request("DELETE", String.format(Locale.getDefault(), "/%s", indexName));
                // TODO: remove PERMISSIVE option after moving system index access to REST API call
                RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
                options.setWarningsHandler(WarningsHandler.PERMISSIVE);
                request.setOptions(options.build());
                adminClient().performRequest(request);
            }
        }
    }


    public List<String> getAlertIndices(String detectorType) throws IOException {
        Response response = client().performRequest(new Request("GET", "/_cat/indices/" + DetectorMonitorConfig.getAllAlertsIndicesPattern(detectorType) + "?format=json"));
        XContentParser xcp = createParser(XContentType.JSON.xContent(), response.getEntity().getContent());
        List<Object> responseList = xcp.list();
        List<String> indices = new ArrayList<>();
        for (Object o : responseList) {
            if (o instanceof Map) {
                ((Map<?, ?>) o).forEach((BiConsumer<Object, Object>)
                        (o1, o2) -> {
                            if (o1.equals("index")) {
                                indices.add((String) o2);
                            }
                        });
            }
        }
        return indices;
    }

    public List<String> getIocFindingIndices() throws IOException {
        Response response = client().performRequest(new Request("GET", "/_cat/indices/" + IocFindingService.IOC_FINDING_INDEX_PATTERN_REGEXP + "?format=json"));
        XContentParser xcp = createParser(XContentType.JSON.xContent(), response.getEntity().getContent());
        List<Object> responseList = xcp.list();
        List<String> indices = new ArrayList<>();
        for (Object o : responseList) {
            if (o instanceof Map) {
                ((Map<?, ?>) o).forEach((BiConsumer<Object, Object>)
                        (o1, o2) -> {
                            if (o1.equals("index")) {
                                indices.add((String) o2);
                            }
                        });
            }
        }
        return indices;
    }

    public List<String> getIocIndices() throws IOException {
        Response response = client().performRequest(new Request("GET", "/_cat/indices/" + IOC_ALL_INDEX_PATTERN + "?format=json"));
        XContentParser xcp = createParser(XContentType.JSON.xContent(), response.getEntity().getContent());
        List<Object> responseList = xcp.list();
        List<String> indices = new ArrayList<>();
        for (Object o : responseList) {
            if (o instanceof Map) {
                ((Map<?, ?>) o).forEach((BiConsumer<Object, Object>)
                        (o1, o2) -> {
                            if (o1.equals("index")) {
                                indices.add((String) o2);
                            }
                        });
            }
        }
        return indices;
    }

    public List<String> getQueryIndices(String detectorType) throws IOException {
        Response response = client().performRequest(new Request("GET", "/_cat/indices/" + DetectorMonitorConfig.getRuleIndex(detectorType) + "*?format=json"));
        XContentParser xcp = createParser(XContentType.JSON.xContent(), response.getEntity().getContent());
        List<Object> responseList = xcp.list();
        List<String> indices = new ArrayList<>();
        for (Object o : responseList) {
            if (o instanceof Map) {
                ((Map<?, ?>) o).forEach((BiConsumer<Object, Object>)
                        (o1, o2) -> {
                            if (o1.equals("index")) {
                                indices.add((String) o2);
                            }
                        });
            }
        }
        return indices;
    }


    public List<String> getFindingIndices(String detectorType) throws IOException {
        Response response = client().performRequest(new Request("GET", "/_cat/indices/" + DetectorMonitorConfig.getAllFindingsIndicesPattern(detectorType) + "?format=json"));
        XContentParser xcp = createParser(XContentType.JSON.xContent(), response.getEntity().getContent());
        List<Object> responseList = xcp.list();
        List<String> indices = new ArrayList<>();
        for (Object o : responseList) {
            if (o instanceof Map) {
                ((Map<?, ?>) o).forEach((BiConsumer<Object, Object>)
                        (o1, o2) -> {
                            if (o1.equals("index")) {
                                indices.add((String) o2);
                            }
                        });
            }
        }
        return indices;
    }

    public List<String> getCorrelationHistoryIndices() throws IOException {
        Response response = client().performRequest(new Request("GET", "/_cat/indices/" + CorrelationIndices.CORRELATION_HISTORY_INDEX_PATTERN_REGEXP + "?format=json"));
        XContentParser xcp = createParser(XContentType.JSON.xContent(), response.getEntity().getContent());
        List<Object> responseList = xcp.list();
        List<String> indices = new ArrayList<>();
        for (Object o : responseList) {
            if (o instanceof Map) {
                ((Map<?, ?>) o).forEach((BiConsumer<Object, Object>)
                        (o1, o2) -> {
                            if (o1.equals("index")) {
                                indices.add((String) o2);
                            }
                        });
            }
        }
        return indices;
    }

    public void updateClusterSetting(String setting, String value) throws IOException {
        String settingJson = "{\n" +
                "    \"persistent\" : {" +
                "        \"%s\": \"%s\"" +
                "    }" +
                "}";
        settingJson = String.format(settingJson, setting, value);
        makeRequest(client(), "PUT", "_cluster/settings", Collections.emptyMap(), new StringEntity(settingJson, ContentType.APPLICATION_JSON), new BasicHeader("Content-Type", "application/json"));
    }

    public void acknowledgeAlert(String alertId, String detectorId) throws IOException {
        String body = String.format(Locale.getDefault(), "{\"alerts\":[\"%s\"]}", alertId);
        Request post = new Request("POST", String.format(
                Locale.getDefault(),
                "%s/%s/_acknowledge/alerts",
                SecurityAnalyticsPlugin.DETECTOR_BASE_URI,
                detectorId));
        post.setJsonEntity(body);
        Response ackAlertsResponse = client().performRequest(post);
        assertNotNull(ackAlertsResponse);
        Map<String, Object> ackAlertsResponseMap = entityAsMap(ackAlertsResponse);
        assertTrue(((ArrayList<String>) ackAlertsResponseMap.get("missing")).isEmpty());
        assertTrue(((ArrayList<AlertDto>) ackAlertsResponseMap.get("failed")).isEmpty());
        assertEquals(((ArrayList<AlertDto>) ackAlertsResponseMap.get("acknowledged")).size(), 1);
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
        //response = client().performRequest(new Request("POST", "_refresh"));
        //assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }


    private Map<String, Object> getIndexAPI(String index) throws IOException {
        Response resp = makeRequest(client(), "GET", "/" + index + "?expand_wildcards=all", Collections.emptyMap(), null);
        return asMap(resp);
    }

    private Map<String, Object> getIndexSettingsAPI(String index) throws IOException {
        Response resp = makeRequest(client(), "GET", "/" + index + "/_settings?expand_wildcards=all", Collections.emptyMap(), null);
        Map<String, Object> respMap = asMap(resp);
        return respMap;
    }

    protected void doRollover(String datastreamName) throws IOException {
        Response response = makeRequest(client(), "POST", datastreamName + "/_rollover", Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    protected void createComponentTemplateWithMappings(String componentTemplateName, String mappings) throws IOException {

        String body = "{\n" +
                "    \"template\" : {" +
                "        \"mappings\": {%s}" +
                "    }" +
                "}";
        body = String.format(body, mappings);
        Response response = makeRequest(
                client(),
                "PUT",
                "_component_template/" + componentTemplateName,
                Collections.emptyMap(),
                new StringEntity(body, ContentType.APPLICATION_JSON),
                new BasicHeader("Content-Type", "application/json")
        );
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    protected void createComposableIndexTemplate(String templateName, List<String> indexPatterns, String componentTemplateName, String mappings, boolean isDatastream) throws IOException {
        createComposableIndexTemplate(templateName, indexPatterns, componentTemplateName, mappings, isDatastream, 0);
    }

    protected void createComposableIndexTemplate(String templateName, List<String> indexPatterns, String componentTemplateName, String mappings, boolean isDatastream, int priority) throws IOException {

        String body = "{\n" +
                (isDatastream ? "\"data_stream\": { }," : "") +
                "    \"index_patterns\": [" +
                indexPatterns.stream().collect(
                        Collectors.joining(",", "\"", "\"")) +
                "]," +
                (componentTemplateName == null ? ("\"template\": {\"mappings\": {" + mappings + "}},") : "") +
                (componentTemplateName != null ? ("\"composed_of\": [\"" + componentTemplateName + "\"],") : "") +
                "\"priority\":" + priority +
                "}";
        Response response = makeRequest(
                client(),
                "PUT",
                "_index_template/" + templateName,
                Collections.emptyMap(),
                new StringEntity(body, ContentType.APPLICATION_JSON),
                new BasicHeader("Content-Type", "application/json")
        );
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    protected Map<String, Object> getIndexMappingsAPIFlat(String indexName) throws IOException {
        Request request = new Request("GET", indexName + "/_mapping");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = (Map<String, Object>) responseAsMap(response).values().iterator().next();

        MappingsTraverser mappingsTraverser = new MappingsTraverser((Map<String, Object>) respMap.get("mappings"), Set.of());
        Map<String, Object> flatMappings = mappingsTraverser.traverseAndCopyAsFlat();
        return (Map<String, Object>) flatMappings.get("properties");
    }

    protected Map<String, Object> getIndexMappingsAPI(String indexName) throws IOException {
        Request request = new Request("GET", indexName + "/_mapping");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = (Map<String, Object>) responseAsMap(response).values().iterator().next();
        return (Map<String, Object>) respMap.get("mappings");
    }

    protected Map<String, Object> getIndexMappingsSAFlat(String indexName) throws IOException {
        Request request = new Request("GET", MAPPER_BASE_URI + "?index_name=" + indexName);
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = (Map<String, Object>) responseAsMap(response).values().iterator().next();

        MappingsTraverser mappingsTraverser = new MappingsTraverser((Map<String, Object>) respMap.get("mappings"), Set.of());
        Map<String, Object> flatMappings = mappingsTraverser.traverseAndCopyAsFlat();
        return (Map<String, Object>) flatMappings.get("properties");
    }


    protected void createMappingsAPI(String indexName, String topicName) throws IOException {
        Request request = new Request("POST", MAPPER_BASE_URI);
        // both req params and req body are supported
        request.setJsonEntity(
                "{ \"index_name\":\"" + indexName + "\"," +
                        "  \"rule_topic\":\"" + topicName + "\", " +
                        "  \"partial\":true" +
                        "}"
        );
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    protected String getDatastreamWriteIndex(String datastream) throws IOException {
        Response response = makeRequest(client(), "GET", "_data_stream/" + datastream, Collections.emptyMap(), null);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respAsMap = responseAsMap(response);
        if (respAsMap.containsKey("data_streams")) {
            respAsMap = ((ArrayList<HashMap>) respAsMap.get("data_streams")).get(0);
            List<Map<String, Object>> indices = (List<Map<String, Object>>) respAsMap.get("indices");
            Map<String, Object> index = indices.get(indices.size() - 1);
            return (String) index.get("index_name");
        } else {
            respAsMap = (Map<String, Object>) respAsMap.get(datastream);
        }
        String[] indices = (String[]) respAsMap.get("indices");
        return indices[indices.length - 1];
    }

    protected void createDatastreamAPI(String datastreamName) throws IOException {
        //PUT _data_stream/my-data-stream
        Request request = new Request("PUT", "_data_stream/" + datastreamName);
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }


    protected void deleteDatastreamAPI(String datastreamName) throws IOException {
        Request request = new Request("DELETE", "_data_stream/" + datastreamName);
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
    }

    protected void createSampleDatastream(String datastreamName, String mappings) throws IOException {
        createSampleDatastream(datastreamName, mappings, true);
    }

    protected void createSampleDatastream(String datastreamName, String mappings, boolean useComponentTemplate) throws IOException {

        String indexPattern = datastreamName + "*";

        String componentTemplateMappings = "\"properties\": {" +
                "  \"netflow.destination_transport_port\":{ \"type\": \"long\" }," +
                "  \"netflow.destination_ipv4_address\":{ \"type\": \"ip\" }" +
                "}";

        if (mappings != null) {
            componentTemplateMappings = mappings;
        }

        if (useComponentTemplate) {
            // Setup index_template
            createComponentTemplateWithMappings(
                    "my_ds_component_template-" + datastreamName,
                    componentTemplateMappings
            );
        }
        createComposableIndexTemplate(
                "my_index_template_ds-" + datastreamName,
                List.of(indexPattern),
                useComponentTemplate ? "my_ds_component_template-" + datastreamName : null,
                mappings,
                true
        );

        createDatastreamAPI(datastreamName);
    }

    protected void restoreAlertsFindingsIMSettings() throws IOException {
        updateClusterSetting(ALERT_HISTORY_ROLLOVER_PERIOD.getKey(), "720m");
        updateClusterSetting(ALERT_HISTORY_MAX_DOCS.getKey(), "100000");
        updateClusterSetting(ALERT_HISTORY_INDEX_MAX_AGE.getKey(), "60d");
        updateClusterSetting(ALERT_HISTORY_RETENTION_PERIOD.getKey(), "60d");

        updateClusterSetting(FINDING_HISTORY_ROLLOVER_PERIOD.getKey(), "720m");
        updateClusterSetting(FINDING_HISTORY_MAX_DOCS.getKey(), "100000");
        updateClusterSetting(FINDING_HISTORY_INDEX_MAX_AGE.getKey(), "60d");
        updateClusterSetting(FINDING_HISTORY_RETENTION_PERIOD.getKey(), "60d");

    }

    protected void enableOrDisableWorkflow(String trueOrFalse) throws IOException {
        Request request = new Request("PUT", "_cluster/settings");
        String entity = "{\"persistent\":{\"plugins.security_analytics.filter_by_backend_roles\" : " + trueOrFalse + "}}";
        request.setJsonEntity(entity);
        client().performRequest(request);
    }

    public List<String> getThreatIntelFeedIocs(int num) throws IOException {
        String request = getMatchAllSearchRequestString(num);
        SearchResponse res = executeSearchAndGetResponse(".opensearch-sap-threat-intel*", request, false);
        return getTifdList(res, xContentRegistry()).stream().map(it -> it.getIocValue()).collect(Collectors.toList());
    }

    public String getMatchAllSearchRequestString(int num) {
        return "{\n" +
                "\"size\"  : " + num + "," +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
    }

    protected CorrelationEngineRestApiIT.LogIndices createIndices() throws IOException {
        CorrelationEngineRestApiIT.LogIndices indices = new CorrelationEngineRestApiIT.LogIndices();
        indices.adLdapLogsIndex = createTestIndex("ad_logs", adLdapLogMappings());
        indices.s3AccessLogsIndex = createTestIndex("s3_access_logs", s3AccessLogMappings());
        indices.appLogsIndex = createTestIndex("app_logs", appLogMappings());
        indices.windowsIndex = createTestIndex(randomIndex(), windowsIndexMapping());
        indices.vpcFlowsIndex = createTestIndex("vpc_flow", vpcFlowMappings());
        return indices;
    }

    protected String createNetworkToWindowsFieldBasedRule(CorrelationEngineRestApiIT.LogIndices indices) throws IOException {
        CorrelationQuery query1 = new CorrelationQuery(indices.vpcFlowsIndex, null, "network", "srcaddr");
        CorrelationQuery query4 = new CorrelationQuery(indices.windowsIndex, null, "test_windows", "SourceIp");

        CorrelationRule rule = new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, "network to windows", List.of(query1, query4), 300000L, null);
        Request request = new Request("POST", "/_plugins/_security_analytics/correlation/rules");
        request.setJsonEntity(toJsonString(rule));
        Response response = client().performRequest(request);

        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        return entityAsMap(response).get("_id").toString();
    }

    protected String createNetworkToWindowsFilterQueryBasedRule(LogIndices indices) throws IOException {
        CorrelationQuery query1 = new CorrelationQuery(indices.vpcFlowsIndex, "srcaddr:1.2.3.4", "network", null);
        CorrelationQuery query4 = new CorrelationQuery(indices.windowsIndex, "SourceIp:1.2.3.4", "test_windows", null);

        CorrelationRule rule = new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, "network to windows", List.of(query1, query4), 300000L, null);
        Request request = new Request("POST", "/_plugins/_security_analytics/correlation/rules");
        request.setJsonEntity(toJsonString(rule));
        Response response = client().performRequest(request);

        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        return entityAsMap(response).get("_id").toString();
    }

    protected String createNetworkToCustomLogTypeFieldBasedRule(LogIndices indices, String customLogTypeName, String customLogTypeIndex) throws IOException {
        CorrelationQuery query1 = new CorrelationQuery(indices.vpcFlowsIndex, null, "network", "srcaddr");
        CorrelationQuery query4 = new CorrelationQuery(customLogTypeIndex, null, customLogTypeName, "SourceIp");

        CorrelationRule rule = new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, "network to custom log type", List.of(query1, query4), 300000L, null);
        Request request = new Request("POST", "/_plugins/_security_analytics/correlation/rules");
        request.setJsonEntity(toJsonString(rule));
        Response response = client().performRequest(request);

        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        return entityAsMap(response).get("_id").toString();
    }

    protected String createNetworkToAdLdapToWindowsRule(LogIndices indices) throws IOException {
        CorrelationQuery query1 = new CorrelationQuery(indices.vpcFlowsIndex, "dstaddr:4.5.6.7", "network", null);
        CorrelationQuery query2 = new CorrelationQuery(indices.adLdapLogsIndex, "ResultType:50126", "ad_ldap", null);
        CorrelationQuery query4 = new CorrelationQuery(indices.windowsIndex, "Domain:NTAUTHORI*", "test_windows", null);

        CorrelationRule rule = new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, "network to ad_ldap to windows", List.of(query1, query2, query4), 300000L, null);
        Request request = new Request("POST", "/_plugins/_security_analytics/correlation/rules");
        request.setJsonEntity(toJsonString(rule));
        Response response = client().performRequest(request);

        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        return entityAsMap(response).get("_id").toString();
    }

    protected String createNetworkToAdLdapToWindowsRuleWithTrigger(LogIndices indices) throws IOException {
        CorrelationQuery query1 = new CorrelationQuery(indices.vpcFlowsIndex, "dstaddr:4.5.6.7", "network", null);
        CorrelationQuery query2 = new CorrelationQuery(indices.adLdapLogsIndex, "ResultType:50126", "ad_ldap", null);
        CorrelationQuery query4 = new CorrelationQuery(indices.windowsIndex, "Domain:NTAUTHORI*", "test_windows", null);
        List<Action> actions = new ArrayList<>();
        CorrelationRuleTrigger trigger = new CorrelationRuleTrigger("trigger-123", "Trigger 1", "high", actions);

        CorrelationRule rule = new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, "network to ad_ldap to windows", List.of(query1, query2, query4), 300000L, trigger);
        Request request = new Request("POST", "/_plugins/_security_analytics/correlation/rules");
        request.setJsonEntity(toJsonString(rule));
        Response response = client().performRequest(request);

        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        return entityAsMap(response).get("_id").toString();
    }

    protected String createWindowsToAppLogsToS3LogsRule(LogIndices indices) throws IOException {
        CorrelationQuery query1 = new CorrelationQuery(indices.windowsIndex, "HostName:EC2AMAZ*", "test_windows", null);
        CorrelationQuery query2 = new CorrelationQuery(indices.appLogsIndex, "endpoint:\\/customer_records.txt", "others_application", null);
        CorrelationQuery query4 = new CorrelationQuery(indices.s3AccessLogsIndex, "aws.cloudtrail.eventName:ReplicateObject", "s3", null);

        CorrelationRule rule = new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, "windows to app_logs to s3 logs", List.of(query1, query2, query4), 300000L, null);
        Request request = new Request("POST", "/_plugins/_security_analytics/correlation/rules");
        request.setJsonEntity(toJsonString(rule));
        Response response = client().performRequest(request);

        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        return entityAsMap(response).get("_id").toString();
    }

    protected String createCloudtrailFieldBasedRule(String index, String field, Long timeWindow) throws IOException {
        CorrelationQuery query1 = new CorrelationQuery(index, "EventName:CreateUser", "cloudtrail", field);
        CorrelationQuery query2 = new CorrelationQuery(index, "EventName:DeleteUser", "cloudtrail", field);

        CorrelationRule rule = new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, "cloudtrail field based", List.of(query1, query2), timeWindow, null);
        Request request = new Request("POST", "/_plugins/_security_analytics/correlation/rules");
        request.setJsonEntity(toJsonString(rule));
        Response response = client().performRequest(request);

        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        return entityAsMap(response).get("_id").toString();
    }

    protected String createCloudtrailFieldBasedRuleWithTrigger(String index, String field, Long timeWindow) throws IOException {
        CorrelationQuery query1 = new CorrelationQuery(index, "EventName:CreateUser", "cloudtrail", field);
        CorrelationQuery query2 = new CorrelationQuery(index, "EventName:DeleteUser", "cloudtrail", field);
        List<Action> actions = new ArrayList<>();
        CorrelationRuleTrigger trigger = new CorrelationRuleTrigger("trigger-345", "Trigger 2", "high", actions);
        CorrelationRule rule = new CorrelationRule("correlation-rule-1", CorrelationRule.NO_VERSION, "cloudtrail field based", List.of(query1, query2), timeWindow, trigger);
        Request request = new Request("POST", "/_plugins/_security_analytics/correlation/rules");
        request.setJsonEntity(toJsonString(rule));
        Response response = client().performRequest(request);

        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        return entityAsMap(response).get("_id").toString();
    }

    @SuppressWarnings("unchecked")
    protected String createVpcFlowDetector(String indexName) throws IOException {
        Detector vpcFlowDetector = randomDetectorWithInputsAndTriggersAndType(List.of(new DetectorInput("vpc flow detector for security analytics", List.of(indexName), List.of(),
                        getPrePackagedRules("network").stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("network"), List.of(), List.of(), List.of(), List.of(), List.of())), "network");

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(vpcFlowDetector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        return ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
    }

    @SuppressWarnings("unchecked")
    protected String createAdLdapDetector(String indexName) throws IOException {
        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{\n" +
                        "  \"index_name\": \"" + indexName + "\",\n" +
                        "  \"rule_topic\": \"ad_ldap\",\n" +
                        "  \"partial\": true,\n" +
                        "  \"alias_mappings\": {\n" +
                        "    \"properties\": {\n" +
                        "      \"azure.signinlogs.properties.user_id\": {\n" +
                        "        \"path\": \"azure.signinlogs.props.user_id\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      },\n" +
                        "      \"azure-platformlogs-result_type\": {\n" +
                        "        \"path\": \"azure.platformlogs.result_type\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      },\n" +
                        "      \"azure-signinlogs-result_description\": {\n" +
                        "        \"path\": \"azure.signinlogs.result_description\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      },\n" +
                        "      \"timestamp\": {\n" +
                        "        \"path\": \"creationTime\",\n" +
                        "        \"type\": \"alias\"\n" +
                        "      }\n" +
                        "    }\n" +
                        "  }\n" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusLine().getStatusCode());

        Detector adLdapDetector = randomDetectorWithInputsAndTriggersAndType(List.of(new DetectorInput("ad_ldap logs detector for security analytics", List.of(indexName), List.of(),
                        getPrePackagedRules("ad_ldap").stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("ad_ldap"), List.of(), List.of(), List.of(), List.of(), List.of())), "ad_ldap");

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(adLdapDetector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        return ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
    }

    @SuppressWarnings("unchecked")
    protected String createTestWindowsDetector(String indexName) throws IOException {
        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + indexName + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusLine().getStatusCode());

        Detector windowsDetector = randomDetectorWithInputsAndTriggers(List.of(new DetectorInput("windows detector for security analytics", List.of(indexName), List.of(),
                        getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of(randomDetectorType()), List.of(), List.of(), List.of(), List.of(), List.of())));

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(windowsDetector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        return ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
    }

    @SuppressWarnings("unchecked")
    protected String createAppLogsDetector(String indexName) throws IOException {
        Detector appLogsDetector = randomDetectorWithInputsAndTriggersAndType(List.of(new DetectorInput("app logs detector for security analytics", List.of(indexName), List.of(),
                        getPrePackagedRules("others_application").stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("others_application"), List.of(), List.of(), List.of(), List.of(), List.of())), "others_application");

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(appLogsDetector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        return ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
    }

    @SuppressWarnings("unchecked")
    protected String createS3Detector(String indexName) throws IOException {
        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{\n" +
                        "  \"index_name\": \"s3_access_logs\",\n" +
                        "  \"rule_topic\": \"s3\",\n" +
                        "  \"partial\": true,\n" +
                        "  \"alias_mappings\": {\n" +
                        "    \"properties\": {\n" +
                        "      \"aws-cloudtrail-event_source\": {\n" +
                        "        \"type\": \"alias\",\n" +
                        "        \"path\": \"aws.cloudtrail.event_source\"\n" +
                        "      },\n" +
                        "      \"aws.cloudtrail.event_name\": {\n" +
                        "        \"type\": \"alias\",\n" +
                        "        \"path\": \"aws.cloudtrail.event_name\"\n" +
                        "      }\n" +
                        "    }\n" +
                        "  }\n" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(RestStatus.OK.getStatus(), response.getStatusLine().getStatusCode());

        Detector s3AccessLogsDetector = randomDetectorWithInputsAndTriggersAndType(List.of(new DetectorInput("s3 access logs detector for security analytics", List.of(indexName), List.of(),
                        getPrePackagedRules("s3").stream().map(DetectorRule::new).collect(Collectors.toList()))),
                List.of(new DetectorTrigger(null, "test-trigger", "1", List.of("s3"), List.of(), List.of(), List.of(), List.of(), List.of())), "s3");

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(s3AccessLogsDetector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        return ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
    }

    /**
     * We need to be able to dump the jacoco coverage before cluster is shut down.
     * The new internal testing framework removed some of the gradle tasks we were listening to
     * to choose a good time to do it. This will dump the executionData to file after each test.
     * TODO: This is also currently just overwriting integTest.exec with the updated execData without
     * resetting after writing each time. This can be improved to either write an exec file per test
     * or by letting jacoco append to the file
     */
    public interface IProxy {
        byte[] getExecutionData(boolean reset);

        void dump(boolean reset);

        void reset();
    }


    @AfterClass
    public static void dumpCoverage() throws IOException, MalformedObjectNameException {
        // jacoco.dir is set in esplugin-coverage.gradle, if it doesn't exist we don't
        // want to collect coverage so we can return early
        String jacocoBuildPath = System.getProperty("jacoco.dir");
        if (Strings.isNullOrEmpty(jacocoBuildPath)) {
            return;
        }

        String serverUrl = "service:jmx:rmi:///jndi/rmi://127.0.0.1:7777/jmxrmi";
        try (JMXConnector connector = JMXConnectorFactory.connect(new JMXServiceURL(serverUrl))) {
            IProxy proxy = MBeanServerInvocationHandler.newProxyInstance(
                    connector.getMBeanServerConnection(), new ObjectName("org.jacoco:type=Runtime"), IProxy.class,
                    false);

            Path path = org.opensearch.common.io.PathUtils.get(jacocoBuildPath + "/integTestRunner.exec");
            Files.write(path, proxy.getExecutionData(false));
        } catch (Exception ex) {
            throw new RuntimeException("Failed to dump coverage: " + ex);
        }
    }

    protected Map<String, Map<String, Boolean>> createTestAlias(
            String alias, int numOfAliasIndices, boolean includeWriteIndex
    ) throws IOException {
        return createTestAlias(
                alias,
                randomAliasIndices(alias, numOfAliasIndices, includeWriteIndex),
                true
        );
    }

    protected Map<String, Map<String, Boolean>> createTestAlias(
            String alias, Map<String, Boolean> indices, boolean createIndices) throws IOException {
        Map<String, Boolean> indicesMap = new java.util.HashMap<>(indices);
        Map<String, Map<String, Boolean>> result = new java.util.HashMap<>();
        XContentBuilder indicesJson = XContentFactory.jsonBuilder()
                .startObject()
                .startArray("actions");
        for (Map.Entry<String, Boolean> entry : indicesMap.entrySet()) {
            if (createIndices)
                createTestIndex(entry.getKey(), windowsIndexMapping());
            boolean isWriteIndex = entry.getValue();
            indicesJson.startObject()
                    .startObject("add")
                    .field("index", entry.getKey())
                    .field("alias", alias)
                    .field("is_write_index", isWriteIndex)
                    .endObject()
                    .endObject();
        }
        indicesJson.endArray().endObject();
        makeRequest(client(), "POST", "/_aliases", Collections.emptyMap(), new StringEntity(indicesJson.toString(), ContentType.APPLICATION_JSON));
        result.put(alias, indicesMap);
        return result;
    }


    protected static Map<String, Boolean> randomAliasIndices(
            String alias, int num, boolean includeWriteIndex) {
        Map<String, Boolean> indices = new HashMap<>();
        int writeIndex = randomIntBetween(0, num - 1);
        for (int i = 0; i < num; i++) {
            String indexName = randomAlphaOfLength(10).toLowerCase(Locale.ROOT);
            while (indexName.equals(alias) || indices.containsKey(indexName)) {
                indexName = randomAlphaOfLength(10).toLowerCase(Locale.ROOT);
            }
            boolean isWriteIndex = includeWriteIndex && i == writeIndex;
            indices.put(indexName, isWriteIndex);
        }
        return indices;
    }

    public static class LogIndices {
        public String vpcFlowsIndex;
        public String adLdapLogsIndex;
        public String windowsIndex;
        public String appLogsIndex;
        public String s3AccessLogsIndex;
    }
}