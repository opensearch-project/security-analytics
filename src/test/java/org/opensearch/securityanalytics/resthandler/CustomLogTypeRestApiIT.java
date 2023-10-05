/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.http.HttpStatus;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.junit.Assert;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.TestHelpers;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.opensearch.securityanalytics.TestHelpers.*;

public class CustomLogTypeRestApiIT extends SecurityAnalyticsRestTestCase {

    @SuppressWarnings("unchecked")
    public void testCreateACustomLogType() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        createdId = responseBody.get("_id").toString();

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", customLogType.getName(), detectorTypeInResponse);

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        String monitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
        indexDoc(index, "1", randomDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
    }

    @SuppressWarnings("unchecked")
    public void testCreateACustomLogTypeWithMappings() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{\"properties\":{\"event_uid\":{\"type\":\"alias\",\"path\":\"EventID\"}}}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRuleWithAlias();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        createdId = responseBody.get("_id").toString();

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", customLogType.getName(), detectorTypeInResponse);

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        String monitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
        indexDoc(index, "1", randomDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
    }

    @SuppressWarnings("unchecked")
    public void testEditACustomLogTypeDescription() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String logTypeId = responseBody.get("_id").toString();
        int correlationId = Integer.parseInt(((Map<String, Object>)(((Map<String, Object>) responseBody.get("logType")).get("tags"))).get("correlation_id").toString());
        Assert.assertEquals(customLogType.getDescription(), ((Map<String, Object>) responseBody.get("logType")).get("description"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        customLogType = TestHelpers.randomCustomLogType(null, "updated desc", null, "Custom");
        Response updatedResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + logTypeId, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.OK, restStatus(updatedResponse));

        responseBody = asMap(updatedResponse);
        Assert.assertEquals(customLogType.getDescription(), ((Map<String, Object>) responseBody.get("logType")).get("description"));
        Assert.assertEquals(correlationId, Integer.parseInt(((Map<String, Object>)(((Map<String, Object>) responseBody.get("logType")).get("tags"))).get("correlation_id").toString()));
    }

    @SuppressWarnings("unchecked")
    public void testEditACustomLogTypeCategory() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String logTypeId = responseBody.get("_id").toString();
        int correlationId = Integer.parseInt(((Map<String, Object>)(((Map<String, Object>) responseBody.get("logType")).get("tags"))).get("correlation_id").toString());
        Assert.assertEquals(customLogType.getCategory(), ((Map<String, Object>) responseBody.get("logType")).get("category"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        customLogType = TestHelpers.randomCustomLogType(null, null, "Access Management", "Custom");
        Response updatedResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + logTypeId, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.OK, restStatus(updatedResponse));

        responseBody = asMap(updatedResponse);
        Assert.assertEquals(customLogType.getCategory(), ((Map<String, Object>) responseBody.get("logType")).get("category"));
        Assert.assertEquals(correlationId, Integer.parseInt(((Map<String, Object>)(((Map<String, Object>) responseBody.get("logType")).get("tags"))).get("correlation_id").toString()));
    }

    @SuppressWarnings("unchecked")
    public void testEditACustomLogTypeWithoutDetectors() throws IOException {
        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String logTypeId = responseBody.get("_id").toString();
        Assert.assertEquals(customLogType.getDescription(), ((Map<String, Object>) responseBody.get("logType")).get("description"));

        CustomLogType updatedCustomLogType = TestHelpers.randomCustomLogType("updated_name", null, null, "Custom");
        Response updatedResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + logTypeId, Collections.emptyMap(), toHttpEntity(updatedCustomLogType));
        Assert.assertEquals("Update custom log type failed", RestStatus.OK, restStatus(updatedResponse));

        responseBody = asMap(updatedResponse);
        Assert.assertEquals(updatedCustomLogType.getDescription(), ((Map<String, Object>) responseBody.get("logType")).get("description"));
    }

    @SuppressWarnings("unchecked")
    public void testEditACustomLogTypeNameFailsAsDetectorExist() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String logTypeId = responseBody.get("_id").toString();
        Assert.assertEquals(customLogType.getDescription(), ((Map<String, Object>) responseBody.get("logType")).get("description"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        expectThrows(ResponseException.class, () -> {
            CustomLogType updatedCustomLogType = TestHelpers.randomCustomLogType("updated name", null, null, "Custom");
            makeRequest(client(), "PUT", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + logTypeId, Collections.emptyMap(), toHttpEntity(updatedCustomLogType));
        });
    }

    @SuppressWarnings("unchecked")
    public void testEditACustomLogTypeNameFailsAsCustomRuleExist() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String logTypeId = responseBody.get("_id").toString();
        Assert.assertEquals(customLogType.getDescription(), ((Map<String, Object>) responseBody.get("logType")).get("description"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        createdId = responseBody.get("_id").toString();

        Response deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
        Assert.assertEquals("Delete detector failed", RestStatus.OK, restStatus(deleteResponse));

        expectThrows(ResponseException.class, () -> {
            CustomLogType updatedCustomLogType = TestHelpers.randomCustomLogType("updated name", null, null, "Custom");
            makeRequest(client(), "PUT", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + logTypeId, Collections.emptyMap(), toHttpEntity(updatedCustomLogType));
        });
    }

    @SuppressWarnings("unchecked")
    public void testEditACustomLogTypeName() throws IOException, InterruptedException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String logTypeId = responseBody.get("_id").toString();
        Assert.assertEquals(customLogType.getDescription(), ((Map<String, Object>) responseBody.get("logType")).get("description"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        String ruleId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(ruleId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        Response deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
        Assert.assertEquals("Delete detector failed", RestStatus.OK, restStatus(deleteResponse));

        deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + ruleId, Collections.emptyMap(), null);
        Assert.assertEquals("Delete rule failed", RestStatus.OK, restStatus(deleteResponse));
        Thread.sleep(5000);

        CustomLogType updatedCustomLogType = TestHelpers.randomCustomLogType("updated_name", null, null, "Custom");
        Response updatedResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + logTypeId, Collections.emptyMap(), toHttpEntity(updatedCustomLogType));
        responseBody = asMap(updatedResponse);
        Assert.assertEquals(updatedCustomLogType.getName(), ((Map<String, Object>) responseBody.get("logType")).get("name"));
    }

    @SuppressWarnings("unchecked")
    public void testSearchLogTypes() throws IOException, InterruptedException {
        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));
        Thread.sleep(5000);

        String request = "{\n" +
                "  \"query\": {\n" +
                "    \"match_all\": {\n" +
                "    }\n" +
                "  }\n" +
                "}";

        Response searchResponse = makeRequest(client(), "POST", String.format(Locale.getDefault(), "%s/_search", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI),Collections.emptyMap(),
                new StringEntity(request), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Searching rules failed", RestStatus.OK, restStatus(searchResponse));

        Map<String, Object> responseBody = asMap(searchResponse);
        Assert.assertEquals(24, ((Map<String, Object>) ((Map<String, Object>) responseBody.get("hits")).get("total")).get("value"));

        request = "{\n" +
                "  \"query\": {\n" +
                "    \"match\": {\n" +
                "       \"name\": {\"query\": \"" + customLogType.getName() + "\"}" +
                "    }\n" +
                "  }\n" +
                "}";

        searchResponse = makeRequest(client(), "POST", String.format(Locale.getDefault(), "%s/_search", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI),Collections.emptyMap(),
                new StringEntity(request), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Searching rules failed", RestStatus.OK, restStatus(searchResponse));

        responseBody = asMap(searchResponse);
        Assert.assertEquals(1, ((Map<String, Object>) ((Map<String, Object>) responseBody.get("hits")).get("total")).get("value"));
    }

    @SuppressWarnings("unchecked")
    public void testSearchLogTypesByCategory() throws IOException {
        String request = "{\n" +
                "  \"query\": {\n" +
                "    \"match\": {\n" +
                "       \"category\": \"Access Management\"\n" +
                "    }\n" +
                "  }\n" +
                "}";

        Response searchResponse = makeRequest(client(), "POST", String.format(Locale.getDefault(), "%s/_search", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI),Collections.emptyMap(),
                new StringEntity(request), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Searching rules failed", RestStatus.OK, restStatus(searchResponse));

        Map<String, Object> responseBody = asMap(searchResponse);
        Assert.assertEquals(3, ((Map<String, Object>) ((Map<String, Object>) responseBody.get("hits")).get("total")).get("value"));
    }

    @SuppressWarnings("unchecked")
    public void testDeleteCustomLogTypeFailsAsDetectorExist() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String logTypeId = responseBody.get("_id").toString();
        Assert.assertEquals(customLogType.getDescription(), ((Map<String, Object>) responseBody.get("logType")).get("description"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        expectThrows(ResponseException.class, () -> {
            makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + logTypeId, Collections.emptyMap(), new StringEntity(""));
        });
    }

    @SuppressWarnings("unchecked")
    public void testDeleteCustomLogTypeFailsAsRulesExist() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String logTypeId = responseBody.get("_id").toString();
        Assert.assertEquals(customLogType.getDescription(), ((Map<String, Object>) responseBody.get("logType")).get("description"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        createdId = responseBody.get("_id").toString();

        Response deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
        Assert.assertEquals("Delete detector failed", RestStatus.OK, restStatus(deleteResponse));

        expectThrows(ResponseException.class, () -> {
            makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + logTypeId, Collections.emptyMap(), new StringEntity(""));
        });
    }

    @SuppressWarnings("unchecked")
    public void testDeleteCustomLogTypeWithoutDetectors() throws IOException {
        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String logTypeId = responseBody.get("_id").toString();
        Assert.assertEquals(customLogType.getDescription(), ((Map<String, Object>) responseBody.get("logType")).get("description"));

        Response deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + logTypeId, Collections.emptyMap(), new StringEntity(""));
        Assert.assertEquals(200, deleteResponse.getStatusLine().getStatusCode());
    }

    @SuppressWarnings("unchecked")
    public void testDeleteCustomLogType() throws IOException, InterruptedException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String logTypeId = responseBody.get("_id").toString();
        Assert.assertEquals(customLogType.getDescription(), ((Map<String, Object>) responseBody.get("logType")).get("description"));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        String ruleId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(ruleId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        Response deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.DETECTOR_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
        Assert.assertEquals("Delete detector failed", RestStatus.OK, restStatus(deleteResponse));

        deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + ruleId, Collections.emptyMap(), null);
        Assert.assertEquals("Delete rule failed", RestStatus.OK, restStatus(deleteResponse));
        Thread.sleep(5000);
        makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI + "/" + logTypeId, Collections.emptyMap(), new StringEntity(""));
    }

    @SuppressWarnings("unchecked")
    public void testCreateMultipleLogTypes() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        Detector detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        createdId = responseBody.get("_id").toString();

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", customLogType.getName(), detectorTypeInResponse);

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        List<SearchHit> hits = executeSearch(Detector.DETECTORS_INDEX, request);
        SearchHit hit = hits.get(0);

        String monitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        customLogType = TestHelpers.randomCustomLogType("custom-again", null, null, "Custom");
        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        // Execute CreateMappingsAction to add alias mapping for index
        createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + customLogType.getName() + "\", " +
                        "  \"partial\":true, " +
                        "  \"alias_mappings\":{}" +
                        "}"
        );

        response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        rule = randomRule();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        createdId = responseBody.get("_id").toString();

        input = new DetectorInput("custom log type detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                List.of());
        detector = randomDetectorWithInputs(List.of(input), customLogType.getName());

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);
        createdId = responseBody.get("_id").toString();

        detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", customLogType.getName(), detectorTypeInResponse);

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + createdId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);

        String againMonitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);
        indexDoc(index, "1", randomDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);

        indexDoc(index, "2", randomDoc());

        executeResponse = executeAlertingMonitor(againMonitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);

        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
    }

    public void testGetMappingsView() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());
        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        String rule = randomRuleForCustomLogType();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        // Execute GetMappingsViewAction to add alias mapping for index
        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", index);
        request.addParameter("rule_topic", customLogType.getName());
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = responseAsMap(response);
        // Verify alias mappings
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        List<String> unmappedIndexFields = (List<String>) respMap.get("unmapped_index_fields");
        Assert.assertTrue(unmappedFieldAliases.contains("Author"));
        Assert.assertFalse(unmappedIndexFields.contains("EventID"));
    }

    public void testMultipleLogTypesUpdateFieldMappings() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());
        CustomLogType customLogType = TestHelpers.randomCustomLogType("logtype1", null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        String rule = randomRuleForCustomLogType();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        customLogType = TestHelpers.randomCustomLogType("logtype2", null, null, "Custom");
        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));

        rule = randomRuleForCustomLogType();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", customLogType.getName()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        // Execute GetMappingsViewAction to add alias mapping for index
        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", index);
        request.addParameter("rule_topic", "logtype1");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = responseAsMap(response);
        // Verify alias mappings
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        List<String> unmappedIndexFields = (List<String>) respMap.get("unmapped_index_fields");
        Assert.assertTrue(unmappedFieldAliases.contains("Author"));
        Assert.assertFalse(unmappedIndexFields.contains("EventID"));

        // Execute GetMappingsViewAction to add alias mapping for index
        request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", index);
        request.addParameter("rule_topic", "logtype2");
        response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        respMap = responseAsMap(response);
        // Verify alias mappings
        unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        unmappedIndexFields = (List<String>) respMap.get("unmapped_index_fields");
        Assert.assertTrue(unmappedFieldAliases.contains("Author"));
        Assert.assertFalse(unmappedIndexFields.contains("EventID"));
    }

    public void testLogTypeNamesAlwaysLowercase() throws IOException {
        CustomLogType customLogType = TestHelpers.randomCustomLogType("Logtype1", null, null, "Custom");
        expectThrows(ResponseException.class, () -> {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        });
    }

    public void testMultipleLogTypesCannotBeCreatedWithSameName() throws IOException {
        CustomLogType customLogType = TestHelpers.randomCustomLogType("logtype", null, null, "Custom");
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        Assert.assertEquals("Create custom log type failed", RestStatus.CREATED, restStatus(createResponse));
        expectThrows(ResponseException.class, () -> {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        });
    }

    public void testCreateACustomLogTypeInvalidCategory() throws IOException {
        CustomLogType customLogType = TestHelpers.randomCustomLogType(null, null, "Invalid", "Custom");
        expectThrows(ResponseException.class, () -> {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI, Collections.emptyMap(), toHttpEntity(customLogType));
        });
    }
}
