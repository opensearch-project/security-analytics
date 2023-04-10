/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;


import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.Assert;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.aggregation.bucketselectorext.BucketSelectorExtAggregationBuilder;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParser.Token;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.aggregations.AggregatorFactories;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.Rule;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend.AggregationQueries;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;

import static org.opensearch.securityanalytics.TestHelpers.randomDetectorType;
import static org.opensearch.securityanalytics.TestHelpers.countAggregationTestRule;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithInputs;
import static org.opensearch.securityanalytics.TestHelpers.randomDoc;
import static org.opensearch.securityanalytics.TestHelpers.randomEditedRule;
import static org.opensearch.securityanalytics.TestHelpers.randomIndex;
import static org.opensearch.securityanalytics.TestHelpers.randomRule;
import static org.opensearch.securityanalytics.TestHelpers.randomRuleWithErrors;
import static org.opensearch.securityanalytics.TestHelpers.windowsIndexMapping;

public class RuleRestApiIT extends SecurityAnalyticsRestTestCase {

    public void testCreatingARule() throws IOException {
        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.RULE_BASE_URI, createdId), createResponse.getHeader("Location"));

        String index = Rule.CUSTOM_RULES_INDEX;
        String request = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"rule\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"rule.category\": \"" + randomDetectorType().toLowerCase(Locale.ROOT) + "\"}}\n" +
                "          ]\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";
        List<SearchHit> hits = executeSearch(index, request);
        Assert.assertEquals(1, hits.size());

        request = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"rule\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"rule.category\": \"application\"}}\n" +
                "          ]\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";
        hits = executeSearch(index, request);
        Assert.assertEquals(0, hits.size());
    }

    public void testCreatingARule_incorrect_category() throws IOException {
        String rule = randomRule();

        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "unknown_category"),
                    new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
            fail("expected exception due to invalid category");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
            Assert.assertTrue(
                e.getMessage().contains("Invalid rule category")
            );
        }
    }

    public void testCreatingAggregationRule() throws SigmaError, IOException {
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "windows"),
            new StringEntity(countAggregationTestRule()), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.RULE_BASE_URI, createdId), createResponse.getHeader("Location"));

        String index = Rule.CUSTOM_RULES_INDEX;
        String request = "{\n" +
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

        List<SearchHit> hits = executeSearch(index, request);

        XContentParser xcp = XContentFactory.xContent(XContentType.JSON)
            .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE,  hits.get(0).getSourceAsString());
        Rule result = Rule.docParse(xcp, null, null);

        Assert.assertEquals(1, result.getAggregationQueries().size());
        String expected = "{\"aggQuery\":\"{\\\"result_agg\\\":{\\\"terms\\\":{\\\"field\\\":\\\"_index\\\"}}}\",\"bucketTriggerQuery\":\"{\\\"buckets_path\\\":{\\\"_cnt\\\":\\\"_cnt\\\"},\\\"parent_bucket_path\\\":\\\"result_agg\\\",\\\"script\\\":{\\\"source\\\":\\\"params._cnt > 1.0\\\",\\\"lang\\\":\\\"painless\\\"}}\"}";
        Assert.assertEquals(expected, result.getAggregationQueries().get(0).getValue());
    }

    @SuppressWarnings("unchecked")
    public void testCreatingARuleWithWrongSyntax() throws IOException {
        String rule = randomRuleWithErrors();

        try {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                    new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        } catch (ResponseException ex) {
            Map<String, Object> responseBody = asMap(ex.getResponse());
            String reason = ((Map<String, Object>) responseBody.get("error")).get("reason").toString();
            Assert.assertEquals("{\"error\":\"Sigma rule must have a log source\",\"error\":\"Sigma rule must have a detection definitions\"}", reason);
        }
    }

    @SuppressWarnings("unchecked")
    public void testSearchingPrepackagedRules() throws IOException {
        String request = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"rule\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"rule.category\": \"" + randomDetectorType().toLowerCase(Locale.ROOT) + "\"}}\n" +
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
        Assert.assertEquals(5, ((Map<String, Object>) ((Map<String, Object>) responseBody.get("hits")).get("total")).get("value"));
    }

    @SuppressWarnings("unchecked")
    public void testSearchingPrepackagedRulesByMitreAttackID() throws IOException {
        String request = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"rule.references\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"rule.references.value\": \"TA0008\"}}\n" +
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
        Assert.assertEquals(9, ((Map<String, Object>) ((Map<String, Object>) responseBody.get("hits")).get("total")).get("value"));
    }

    @SuppressWarnings("unchecked")
    public void testSearchingPrepackagedRulesByPages() throws IOException {
        String request = "{\n" +
                "  \"from\": 10\n," +
                "  \"size\": 20\n," +
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
        Assert.assertEquals(20, ((List<SearchHit>) ((Map<String, Object>) responseBody.get("hits")).get("hits")).size());
    }

    @SuppressWarnings("unchecked")
    public void testSearchingPrepackagedRulesByAuthor() throws IOException {
        String request = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"rule\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"rule.author\": \"Sagie Dulce\"}}\n" +
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
        Assert.assertEquals(17, ((Map<String, Object>) ((Map<String, Object>) responseBody.get("hits")).get("total")).get("value"));
    }

    public void testSearchingCustomRulesWhenNoneExist() throws IOException {
        String request = "{\n" +
                "  \"query\": {\n" +
                "        \"match_all\": {}\n" +
                "    }\n" +
                "}";

        Response searchResponse = makeRequest(client(), "POST", String.format(Locale.getDefault(), "%s/_search", SecurityAnalyticsPlugin.RULE_BASE_URI), Collections.singletonMap("pre_packaged", "false"),
                new StringEntity(request), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Searching rules failed", RestStatus.OK, restStatus(searchResponse));
        Map<String, Object> responseBody = asMap(searchResponse);
        Assert.assertEquals(0, ((Map<String, Object>) ((Map<String, Object>) responseBody.get("hits")).get("total")).get("value"));
    }
    @SuppressWarnings("unchecked")
    public void testSearchingCustomRules() throws IOException {
        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        String request = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"rule\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"rule.category\": \"" + randomDetectorType().toLowerCase(Locale.ROOT) + "\"}}\n" +
                "          ]\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";

        Response searchResponse = makeRequest(client(), "POST", String.format(Locale.getDefault(), "%s/_search", SecurityAnalyticsPlugin.RULE_BASE_URI), Collections.singletonMap("pre_packaged", "false"),
                new StringEntity(request), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Searching rules failed", RestStatus.OK, restStatus(searchResponse));

        Map<String, Object> responseBody = asMap(searchResponse);
        Assert.assertEquals(1, ((Map<String, Object>) ((Map<String, Object>) responseBody.get("hits")).get("total")).get("value"));
    }

    public void testUpdatingUnusedRule() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + createdId, Map.of("category", randomDetectorType()),
                new StringEntity(randomEditedRule()), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Update rule failed", RestStatus.OK, restStatus(updateResponse));
    }

    public void testUpdatingARule_incorrect_category() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        try {
            makeRequest(client(), "PUT", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + createdId, Map.of("category", "unknown_category"),
                    new StringEntity(randomEditedRule()), new BasicHeader("Content-Type", "application/json"));
            fail("expected exception due to invalid category");
        } catch (ResponseException e) {
            assertEquals(HttpStatus.SC_BAD_REQUEST, e.getResponse().getStatusLine().getStatusCode());
            Assert.assertTrue(
                    e.getMessage().contains("Invalid rule category")
            );
        }
    }

    public void testUpdatingUnusedRuleAfterDetectorIndexCreated() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + createdId, Map.of("category", randomDetectorType()),
                new StringEntity(randomEditedRule()), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Update rule failed", RestStatus.OK, restStatus(updateResponse));
    }

    @SuppressWarnings("unchecked")
    public void testUpdatingUsedRule() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(createdId)),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));
        responseBody = asMap(createResponse);
        String detectorId = responseBody.get("_id").toString();

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId + "\"\n" +
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
        Assert.assertEquals(6, noOfSigmaRuleMatches);

        try {
            makeRequest(client(), "PUT", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + createdId, Collections.singletonMap("category", randomDetectorType()),
                    new StringEntity(randomEditedRule()), new BasicHeader("Content-Type", "application/json"));
        } catch (ResponseException ex) {
            Assert.assertTrue(new String(ex.getResponse().getEntity().getContent().readAllBytes())
                    .contains(String.format(Locale.getDefault(), "Rule with id %s is actively used by detectors. Update can be forced by setting forced flag to true", createdId)));
        }

        Response updateResponse = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + createdId, Map.of("category", randomDetectorType(), "forced", "true"),
                new StringEntity(randomEditedRule()), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Update rule failed", RestStatus.OK, restStatus(updateResponse));

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match\":{\n" +
                "        \"_id\": \"" + detectorId + "\"\n" +
                "     }\n" +
                "   }\n" +
                "}";
        hits = executeSearch(Detector.DETECTORS_INDEX, request);
        hit = hits.get(0);

        monitorId = ((List<String>) ((Map<String, Object>) hit.getSourceAsMap().get("detector")).get("monitor_id")).get(0);

        indexDoc(index, "2", randomDoc());

        executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        executeResults = entityAsMap(executeResponse);

        noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(5, noOfSigmaRuleMatches);
    }

    public void testDeletingUnusedRule() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        Response deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
        Assert.assertEquals("Delete rule failed", RestStatus.OK, restStatus(deleteResponse));
    }

    public void testDeletingUnusedRuleAfterDetectorIndexCreated() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);
        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Response deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
        Assert.assertEquals("Delete rule failed", RestStatus.OK, restStatus(deleteResponse));
    }

    public void testDeletingUsedRule() throws IOException {
        String index = createTestIndex(randomIndex(), windowsIndexMapping());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"" + randomDetectorType() + "\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String rule = randomRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        DetectorInput input = new DetectorInput("windows detector for security analytics", List.of("windows"), List.of(new DetectorRule(createdId)),
                getRandomPrePackagedRules().stream().map(DetectorRule::new).collect(Collectors.toList()));
        Detector detector = randomDetectorWithInputs(List.of(input));

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        try {
            makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + createdId, Collections.emptyMap(), null);
        } catch (ResponseException ex) {
            Assert.assertTrue(new String(ex.getResponse().getEntity().getContent().readAllBytes())
                    .contains(String.format(Locale.getDefault(), "Rule with id %s is actively used by detectors. Deletion can be forced by setting forced flag to true", createdId)));
        }

        String request = "{\n" +
                "  \"query\": {\n" +
                "    \"script\": {\n" +
                "      \"script\": \"doc['_id'][0].indexOf('" + createdId + "') > -1\"\n" +
                "    }\n" +
                "  }\n" +
                "}";
        List<SearchHit> hits = executeSearch(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request);
        Assert.assertEquals(2, hits.size());

        Response deleteResponse = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + createdId, Collections.singletonMap("forced", "true"), null);
        Assert.assertEquals("Delete rule failed", RestStatus.OK, restStatus(deleteResponse));

        request = "{\n" +
                "  \"query\": {\n" +
                "    \"script\": {\n" +
                "      \"script\": \"doc['_id'][0].indexOf('" + createdId + "') > -1\"\n" +
                "    }\n" +
                "  }\n" +
                "}";
        hits = executeSearch(DetectorMonitorConfig.getRuleIndex(randomDetectorType()), request);
        Assert.assertEquals(0, hits.size());

        index = Rule.CUSTOM_RULES_INDEX;
        request = "{\n" +
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
        hits = executeSearch(index, request);
        Assert.assertEquals(0, hits.size());
    }

    public void testDeletingNonExistingCustomRule() throws IOException {
        try {
            makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.RULE_BASE_URI + "/" + java.util.UUID.randomUUID(), Collections.emptyMap(), null);
        } catch (ResponseException ex) {
            Assert.assertEquals(404, ex.getResponse().getStatusLine().getStatusCode());
        }
    }

    public void testCustomRuleValidation() throws IOException {
        String rule1 =  "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID: 22\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";

        String rule2 =  "title: Remote Encrypting File System Abuse\n" +
                "id: 5f92fff9-82e2-48eb-8fc1-8b133556a551\n" +
                "description: Detects remote RPC calls to possibly abuse remote encryption service via MS-EFSR\n" +
                "references:\n" +
                "    - https://attack.mitre.org/tactics/TA0008/\n" +
                "    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942\n" +
                "    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-EFSR.md\n" +
                "    - https://github.com/zeronetworks/rpcfirewall\n" +
                "    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/\n" +
                "tags:\n" +
                "    - attack.defense_evasion\n" +
                "status: experimental\n" +
                "author: Sagie Dulce, Dekel Paz\n" +
                "date: 2022/01/01\n" +
                "modified: 2022/01/01\n" +
                "logsource:\n" +
                "    product: rpc_firewall\n" +
                "    category: application\n" +
                "    definition: 'Requirements: install and apply the RPC Firewall to all processes with \"audit:true action:block uuid:df1941c5-fe89-4e79-bf10-463657acf44d or c681d488-d850-11d0-8c52-00c04fd90f7e'\n" +
                "detection:\n" +
                "    selection:\n" +
                "        EventID123: 22\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate usage of remote file encryption\n" +
                "level: high";

        // Create rule #1
        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule1), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String rule1createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, rule1createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.RULE_BASE_URI, rule1createdId), createResponse.getHeader("Location"));
        // Create rule #2
        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", randomDetectorType()),
                new StringEntity(rule2), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        String rule2createdId = responseBody.get("_id").toString();
        createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, rule2createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.RULE_BASE_URI, rule2createdId), createResponse.getHeader("Location"));

        // Create logIndex
        createTestIndex("log_index_123", windowsIndexMapping());
        String validateRulesRequest = "{" +
                "\"index_name\": \"log_index_123\"," +
                "\"rules\": [\"" + rule1createdId + "\",\"" + rule2createdId + "\"]" +
                "}";
        Response validationResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI + "/validate", Collections.EMPTY_MAP, new StringEntity(validateRulesRequest), new BasicHeader("Content-Type", "application/json"));
        responseBody = asMap(validationResponse);
        assertTrue(responseBody.containsKey("nonapplicable_fields"));
        assertEquals(rule2createdId, ((List)responseBody.get("nonapplicable_fields")).get(0));
    }

    public void testGetAllRuleCategories() throws IOException {
        Response response = makeRequest(client(), "GET", SecurityAnalyticsPlugin.RULE_BASE_URI + "/categories", Collections.emptyMap(), null);
        List<Object> categories = (List<Object>) asMap(response).get("rule_categories");
        assertEquals(13, categories.size());
        assertTrue(((Map<String, Object>)categories.get(0)).get("key").equals("ad_ldap"));
        assertTrue(((Map<String, Object>)categories.get(1)).get("key").equals("dns"));
        assertTrue(((Map<String, Object>)categories.get(2)).get("key").equals("network"));
        assertTrue(((Map<String, Object>)categories.get(3)).get("key").equals("apache_access"));
        assertTrue(((Map<String, Object>)categories.get(4)).get("key").equals("cloudtrail"));
        assertTrue(((Map<String, Object>)categories.get(5)).get("key").equals("s3"));
        assertTrue(((Map<String, Object>)categories.get(6)).get("key").equals("windows"));
        assertTrue(((Map<String, Object>)categories.get(7)).get("key").equals("gworkspace"));
        assertTrue(((Map<String, Object>)categories.get(8)).get("key").equals("github"));
        assertTrue(((Map<String, Object>)categories.get(9)).get("key").equals("m365"));
        assertTrue(((Map<String, Object>)categories.get(10)).get("key").equals("okta"));
        assertTrue(((Map<String, Object>)categories.get(11)).get("key").equals("azure"));
        assertTrue(((Map<String, Object>)categories.get(12)).get("key").equals("linux"));
    }
}