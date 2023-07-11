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
import org.opensearch.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.TestHelpers.*;

public class OCSFDetectorRestApiIT extends SecurityAnalyticsRestTestCase {

    @SuppressWarnings("unchecked")
    public void testCloudTrailAPIActivityOCSFDetector() throws IOException {
        String index = createTestIndex("cloudtrail", ocsfCloudtrailMappings());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"cloudtrail\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithInputs(List.of(new DetectorInput("ocsf logs based cloudtrail detector for security analytics", List.of(index), List.of(),
                getPrePackagedRules(Detector.DetectorType.CLOUDTRAIL.getDetectorType()).stream().map(DetectorRule::new).collect(Collectors.toList()))), Detector.DetectorType.CLOUDTRAIL);

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", "cloudtrail", detectorTypeInResponse);

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

        indexDoc(index, "1", ocsfCloudtrailDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
    }

    @SuppressWarnings("unchecked")
    public void testCloudTrailAPIActivityRawDetector() throws IOException {
        String index = createTestIndex("cloudtrail", rawCloudtrailMappings());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"cloudtrail\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithInputs(List.of(new DetectorInput("raw logs based cloudtrail detector for security analytics", List.of(index), List.of(),
                getPrePackagedRules(Detector.DetectorType.CLOUDTRAIL.getDetectorType()).stream().map(DetectorRule::new).collect(Collectors.toList()))), Detector.DetectorType.CLOUDTRAIL);

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", "cloudtrail", detectorTypeInResponse);

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

        indexDoc(index, "1", rawCloudtrailDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
    }

    @SuppressWarnings("unchecked")
    public void testRoute53OCSFDetector() throws IOException {
        String rule = customRoute53Rule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "dns"),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String index = createTestIndex("route53", ocsfRoute53Mappings());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"dns\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithInputs(List.of(new DetectorInput("raw logs based route53 detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                getPrePackagedRules(Detector.DetectorType.DNS.getDetectorType()).stream().map(DetectorRule::new).collect(Collectors.toList()))), Detector.DetectorType.DNS);

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", "dns", detectorTypeInResponse);

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

        indexDoc(index, "1", ocsfRoute53Doc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
    }

    @SuppressWarnings("unchecked")
    public void testRoute53RawDetector() throws IOException {
        String rule = customRoute53Rule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "dns"),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String index = createTestIndex("route53", rawRoute53DnsMappings());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"dns\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithInputs(List.of(new DetectorInput("raw logs based route53 detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                getPrePackagedRules(Detector.DetectorType.DNS.getDetectorType()).stream().map(DetectorRule::new).collect(Collectors.toList()))), Detector.DetectorType.DNS);

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", "dns", detectorTypeInResponse);

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

        indexDoc(index, "1", rawRoute53Doc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
    }

    @SuppressWarnings("unchecked")
    public void testVpcflowOcsfDetector() throws IOException {
        String rule = customVpcFlowRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "vpcflow"),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String index = createTestIndex("vpcflow", ocsfVpcflowMappings());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"vpcflow\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithInputs(List.of(new DetectorInput("raw logs based vpcflow detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                getPrePackagedRules(Detector.DetectorType.DNS.getDetectorType()).stream().map(DetectorRule::new).collect(Collectors.toList()))), Detector.DetectorType.DNS);

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", "dns", detectorTypeInResponse);

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

        indexDoc(index, "1", ocsfVpcflowDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
    }

    @SuppressWarnings("unchecked")
    public void testVpcflowRawDetector() throws IOException {
        String rule = customVpcFlowRule();

        Response createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULE_BASE_URI, Collections.singletonMap("category", "vpcflow"),
                new StringEntity(rule), new BasicHeader("Content-Type", "application/json"));
        Assert.assertEquals("Create rule failed", RestStatus.CREATED, restStatus(createResponse));

        Map<String, Object> responseBody = asMap(createResponse);

        String createdId = responseBody.get("_id").toString();

        String index = createTestIndex("vpcflow", rawVpcFlowMappings());

        // Execute CreateMappingsAction to add alias mapping for index
        Request createMappingRequest = new Request("POST", SecurityAnalyticsPlugin.MAPPER_BASE_URI);
        // both req params and req body are supported
        createMappingRequest.setJsonEntity(
                "{ \"index_name\":\"" + index + "\"," +
                        "  \"rule_topic\":\"vpcflow\", " +
                        "  \"partial\":true" +
                        "}"
        );

        Response response = client().performRequest(createMappingRequest);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        Detector detector = randomDetectorWithInputs(List.of(new DetectorInput("raw logs based vpcflow detector for security analytics", List.of(index), List.of(new DetectorRule(createdId)),
                getPrePackagedRules(Detector.DetectorType.DNS.getDetectorType()).stream().map(DetectorRule::new).collect(Collectors.toList()))), Detector.DetectorType.DNS);

        createResponse = makeRequest(client(), "POST", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, Collections.emptyMap(), toHttpEntity(detector));
        Assert.assertEquals("Create detector failed", RestStatus.CREATED, restStatus(createResponse));

        responseBody = asMap(createResponse);

        createdId = responseBody.get("_id").toString();
        int createdVersion = Integer.parseInt(responseBody.get("_version").toString());
        Assert.assertNotEquals("response is missing Id", Detector.NO_ID, createdId);
        Assert.assertTrue("incorrect version", createdVersion > 0);
        Assert.assertEquals("Incorrect Location header", String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, createdId), createResponse.getHeader("Location"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("rule_topic_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("findings_index"));
        Assert.assertFalse(((Map<String, Object>) responseBody.get("detector")).containsKey("alert_index"));

        String detectorTypeInResponse = (String) ((Map<String, Object>)responseBody.get("detector")).get("detector_type");
        Assert.assertEquals("Detector type incorrect", "dns", detectorTypeInResponse);

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

        indexDoc(index, "1", rawVpcFlowDoc());

        Response executeResponse = executeAlertingMonitor(monitorId, Collections.emptyMap());
        Map<String, Object> executeResults = entityAsMap(executeResponse);

        int noOfSigmaRuleMatches = ((List<Map<String, Object>>) ((Map<String, Object>) executeResults.get("input_results")).get("results")).get(0).size();
        Assert.assertEquals(1, noOfSigmaRuleMatches);
    }

    @SuppressWarnings("unchecked")
    public void testOCSFCloudtrailGetMappingsViewApi() throws IOException {
        String index = createTestIndex("cloudtrail", ocsfCloudtrailMappings());

        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", index);
        request.addParameter("rule_topic", "cloudtrail");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = responseAsMap(response);
        // Verify alias mappings
        Map<String, Object> props = (Map<String, Object>) respMap.get("properties");
        Assert.assertEquals(18, props.size());
        // Verify unmapped index fields
        List<String> unmappedIndexFields = (List<String>) respMap.get("unmapped_index_fields");
        assertEquals(20, unmappedIndexFields.size());
        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(25, unmappedFieldAliases.size());
    }

    @SuppressWarnings("unchecked")
    public void testOCSFVpcflowGetMappingsViewApi() throws IOException {
        String index = createTestIndex("vpcflow", ocsfVpcflowMappings());

        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", index);
        request.addParameter("rule_topic", "vpcflow");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = responseAsMap(response);
        // Verify alias mappings
        Map<String, Object> props = (Map<String, Object>) respMap.get("properties");
        Assert.assertEquals(20, props.size());
        // Verify unmapped index fields
        List<String> unmappedIndexFields = (List<String>) respMap.get("unmapped_index_fields");
        assertEquals(26, unmappedIndexFields.size());
        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(5, unmappedFieldAliases.size());
    }

    @SuppressWarnings("unchecked")
    public void testOCSFRoute53GetMappingsViewApi() throws IOException {
        String index = createTestIndex("route53", ocsfRoute53Mappings());

        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", index);
        request.addParameter("rule_topic", "dns");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = responseAsMap(response);
        // Verify alias mappings
        Map<String, Object> props = (Map<String, Object>) respMap.get("properties");
        Assert.assertEquals(11, props.size());
        // Verify unmapped index fields
        List<String> unmappedIndexFields = (List<String>) respMap.get("unmapped_index_fields");
        assertEquals(28, unmappedIndexFields.size());
        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(11, unmappedFieldAliases.size());
    }

    @SuppressWarnings("unchecked")
    public void testRawCloudtrailGetMappingsViewApi() throws IOException {
        String index = createTestIndex("cloudtrail", rawCloudtrailMappings());

        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", index);
        request.addParameter("rule_topic", "cloudtrail");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = responseAsMap(response);
        // Verify alias mappings
        Map<String, Object> props = (Map<String, Object>) respMap.get("properties");
        Assert.assertEquals(17, props.size());
        // Verify unmapped index fields
        List<String> unmappedIndexFields = (List<String>) respMap.get("unmapped_index_fields");
        assertEquals(17, unmappedIndexFields.size());
        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(26, unmappedFieldAliases.size());
    }

    @SuppressWarnings("unchecked")
    public void testRawVpcflowGetMappingsViewApi() throws IOException {
        String index = createTestIndex("vpcflow", rawVpcFlowMappings());

        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", index);
        request.addParameter("rule_topic", "vpcflow");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = responseAsMap(response);
        // Verify alias mappings
        Map<String, Object> props = (Map<String, Object>) respMap.get("properties");
        Assert.assertEquals(24, props.size());
        // Verify unmapped index fields
        List<String> unmappedIndexFields = (List<String>) respMap.get("unmapped_index_fields");
        assertEquals(5, unmappedIndexFields.size());
        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(1, unmappedFieldAliases.size());
    }

    @SuppressWarnings("unchecked")
    public void testRawRoute53GetMappingsViewApi() throws IOException {
        String index = createTestIndex("route53", rawRoute53DnsMappings());

        Request request = new Request("GET", SecurityAnalyticsPlugin.MAPPINGS_VIEW_BASE_URI);
        // both req params and req body are supported
        request.addParameter("index_name", index);
        request.addParameter("rule_topic", "dns");
        Response response = client().performRequest(request);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        Map<String, Object> respMap = responseAsMap(response);
        // Verify alias mappings
        Map<String, Object> props = (Map<String, Object>) respMap.get("properties");
        Assert.assertEquals(14, props.size());
        // Verify unmapped index fields
        List<String> unmappedIndexFields = (List<String>) respMap.get("unmapped_index_fields");
        assertEquals(6, unmappedIndexFields.size());
        // Verify unmapped field aliases
        List<String> unmappedFieldAliases = (List<String>) respMap.get("unmapped_field_aliases");
        assertEquals(8, unmappedFieldAliases.size());
    }

    private String rawCloudtrailDoc() {
        return "{\n" +
                "      \"eventVersion\": \"1.03\",\n" +
                "      \"userIdentity\": {\n" +
                "        \"type\": \"IAMUser\",\n" +
                "        \"principalId\": \"123456789012\",\n" +
                "        \"arn\": \"arn:aws:iam::123456789012:user/Alice\",\n" +
                "        \"accountId\": \"123456789012\",\n" +
                "        \"accessKeyId\": \"AKIAIOSFODNN7EXAMPLE\",\n" +
                "        \"userName\": \"Alice\"\n" +
                "      },\n" +
                "      \"eventTime\": \"2016-04-01T15:31:48Z\",\n" +
                "      \"eventSource\": \"elasticloadbalancing.amazonaws.com\",\n" +
                "      \"eventName\": \"CreateLoadBalancer\",\n" +
                "      \"awsRegion\": \"us-west-2\",\n" +
                "      \"sourceIPAddress\": \"198.51.100.1\",\n" +
                "      \"userAgent\": \"aws-cli/1.10.10 Python/2.7.9 Windows/7 botocore/1.4.1\",\n" +
                "      \"requestParameters\": {\n" +
                "        \"subnets\": [\n" +
                "          \"subnet-8360a9e7\",\n" +
                "          \"subnet-b7d581c0\"\n" +
                "        ],\n" +
                "        \"securityGroups\": [\n" +
                "          \"sg-5943793c\"\n" +
                "        ],\n" +
                "        \"name\": \"my-load-balancer\",\n" +
                "        \"scheme\": \"internet-facing\"\n" +
                "      },\n" +
                "      \"responseElements\": {\n" +
                "        \"loadBalancers\": [\n" +
                "          {\n" +
                "            \"type\": \"application\",\n" +
                "            \"loadBalancerName\": \"my-load-balancer\",\n" +
                "            \"vpcId\": \"vpc-3ac0fb5f\",\n" +
                "            \"securityGroups\": [\n" +
                "              \"sg-5943793c\"\n" +
                "            ],\n" +
                "            \"state\": {\n" +
                "              \"code\": \"provisioning\"\n" +
                "            },\n" +
                "            \"availabilityZones\": [\n" +
                "              {\n" +
                "                \"subnetId\": \"subnet-8360a9e7\",\n" +
                "                \"zoneName\": \"us-west-2a\"\n" +
                "              },\n" +
                "              {\n" +
                "                \"subnetId\": \"subnet-b7d581c0\",\n" +
                "                \"zoneName\": \"us-west-2b\"\n" +
                "              }\n" +
                "            ],\n" +
                "            \"dNSName\": \"my-load-balancer-1836718677.us-west-2.elb.amazonaws.com\",\n" +
                "            \"canonicalHostedZoneId\": \"Z2P70J7HTTTPLU\",\n" +
                "            \"createdTime\": \"Apr 11, 2016 5:23:50 PM\",\n" +
                "            \"loadBalancerArn\": \"arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/my-load-balancer/ffcddace1759e1d0\",\n" +
                "            \"scheme\": \"internet-facing\"\n" +
                "          }\n" +
                "        ]\n" +
                "      },\n" +
                "      \"requestID\": \"b9960276-b9b2-11e3-8a13-f1ef1EXAMPLE\",\n" +
                "      \"eventID\": \"6f4ab5bd-2daa-4d00-be14-d92efEXAMPLE\",\n" +
                "      \"eventType\": \"AwsApiCall\",\n" +
                "      \"apiVersion\": \"2015-12-01\",\n" +
                "      \"recipientAccountId\": \"123456789012\"\n" +
                "    }";
    }

    private String rawRoute53Doc() {
        return "{\n" +
                "    \"version\": \"1.100000\",\n" +
                "    \"account_id\": \"123456789012\",\n" +
                "    \"region\": \"us-east-1\",\n" +
                "    \"vpc_id\": \"vpc-00000000000000000\",\n" +
                "    \"query_timestamp\": \"2022-10-13T21:02:36Z\",\n" +
                "    \"query_name\": \"ip-127-0-0-62.alert.firewall.canary.\",\n" +
                "    \"query_type\": \"A\",\n" +
                "    \"query_class\": \"IN\",\n" +
                "    \"rcode\": \"NOERROR\",\n" +
                "    \"answers\": [{\n" +
                "        \"Rdata\": \"127.0.0.62\",\n" +
                "        \"Type\": \"A\",\n" +
                "        \"Class\": \"IN\"\n" +
                "    }],\n" +
                "    \"srcaddr\": \"10.200.21.100\",\n" +
                "    \"srcport\": \"15083\",\n" +
                "    \"transport\": \"UDP\",\n" +
                "    \"srcids\": {\n" +
                "        \"resolver_endpoint\": \"rslvr-in-0000000000000000\",\n" +
                "        \"resolver_network_interface\": \"rni-0000000000000000\"\n" +
                "    },\n" +
                "    \"firewall_rule_action\": \"ALERT\",\n" +
                "    \"firewall_rule_group_id\": \"rslvr-frg-000000000000000\",\n" +
                "    \"firewall_domain_list_id\": \"rslvr-fdl-0000000000000\"\n" +
                "}";
    }

    private String rawVpcFlowDoc() {
        return "{\n" +
                "  \"account_id\": \"123456789012\",\n" +
                "  \"action\": \"REJECT\",\n" +
                "  \"az_id\": \"use1-az1\",\n" +
                "  \"bytes\": 40,\n" +
                "  \"dstaddr\": \"172.31.2.52\",\n" +
                "  \"dstport\": 39938,\n" +
                "  \"end\": 1649721788,\n" +
                "  \"flow_direction\": \"ingress\",\n" +
                "  \"instance_id\": \"i-000000000000000000\",\n" +
                "  \"interface_id\": \"eni-000000000000000000\",\n" +
                "  \"log_status\": \"OK\",\n" +
                "  \"packets\": 1,\n" +
                "  \"pkt_dst_aws_service\": \"-\",\n" +
                "  \"pkt_dstaddr\": \"172.31.2.52\",\n" +
                "  \"pkt_src_aws_service\": \"-\",\n" +
                "  \"pkt_srcaddr\": \"1.2.3.4\",\n" +
                "  \"protocol\": 6,\n" +
                "  \"region\": \"us-east-1\",\n" +
                "  \"srcaddr\": \"1.2.3.4\",\n" +
                "  \"srcport\": 56858,\n" +
                "  \"start\": 1649721732,\n" +
                "  \"sublocation_type\": \"-\",\n" +
                "  \"sublocation_id\": \"-\",\n" +
                "  \"subnet_id\": \"subnet-000000000000000000\",\n" +
                "  \"tcp_flags\": 2,\n" +
                "  \"traffic_path\": \"-\",\n" +
                "  \"type\": \"IPv4\",\n" +
                "  \"version\": 5,\n" +
                "  \"vpc_id\": \"vpc-00000000\"\n" +
                "}";
    }

    private String customRoute53Rule() {
        return "title: High DNS Requests Rate\n" +
                "id: b4163085-4001-46a3-a79a-55d8bbbc7a3a\n" +
                "status: experimental\n" +
                "description: High DNS requests amount from host per short period of time\n" +
                "author: Daniil Yugoslavskiy, oscd.community\n" +
                "date: 2019/10/24\n" +
                "modified: 2021/09/21\n" +
                "tags:\n" +
                "    - attack.exfiltration\n" +
                "    - attack.t1048.003\n" +
                "    - attack.command_and_control\n" +
                "    - attack.t1071.004\n" +
                "logsource:\n" +
                "    category: dns\n" +
                "detection:\n" +
                "    selection:\n" +
                "        srcids.resolver_endpoint: 'rslvr-in-0000000000000000'\n" +
                "    timeframe: 1m\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate high DNS requests rate to domain name which should be added to whitelist\n" +
                "level: medium";
    }

    private String customVpcFlowRule() {
        return "title: High DNS Requests Rate\n" +
                "id: b4163085-4001-46a3-a79a-55d8bbbc7a3a\n" +
                "status: experimental\n" +
                "description: High DNS requests amount from host per short period of time\n" +
                "author: Daniil Yugoslavskiy, oscd.community\n" +
                "date: 2019/10/24\n" +
                "modified: 2021/09/21\n" +
                "tags:\n" +
                "    - attack.exfiltration\n" +
                "    - attack.t1048.003\n" +
                "    - attack.command_and_control\n" +
                "    - attack.t1071.004\n" +
                "logsource:\n" +
                "    category: dns\n" +
                "detection:\n" +
                "    selection:\n" +
                "        srcaddr: '1.2.3.4'\n" +
                "    timeframe: 1m\n" +
                "    condition: selection\n" +
                "falsepositives:\n" +
                "    - Legitimate high DNS requests rate to domain name which should be added to whitelist\n" +
                "level: medium";
    }

    private String ocsfRoute53Doc() {
        return "{\n" +
                "  \"metadata\": {\n" +
                "    \"product\": {\n" +
                "      \"version\": \"1.100000\",\n" +
                "      \"name\": \"Route 53\",\n" +
                "      \"feature\": {\n" +
                "        \"name\": \"Resolver Query Logs\"\n" +
                "      },\n" +
                "      \"vendor_name\": \"AWS\"\n" +
                "    },\n" +
                "    \"profiles\": [\n" +
                "      \"cloud\",\n" +
                "      \"security_control\"\n" +
                "    ],\n" +
                "    \"version\": \"1.0.0-rc.2\"\n" +
                "  },\n" +
                "  \"cloud\": {\n" +
                "    \"account_uid\": \"123456789012\",\n" +
                "    \"region\": \"us-east-1\",\n" +
                "    \"provider\": \"AWS\"\n" +
                "  },\n" +
                "  \"src_endpoint\": {\n" +
                "    \"vpc_uid\": \"vpc-00000000000000000\",\n" +
                "    \"ip\": \"10.200.21.100\",\n" +
                "    \"port\": 15083,\n" +
                "    \"instance_uid\": null\n" +
                "  },\n" +
                "  \"time\": 1665694956000,\n" +
                "  \"queries\": {\n" +
                "    \"hostname\": \"ip-127-0-0-62.alert.firewall.canary.\",\n" +
                "    \"type\": \"A\",\n" +
                "    \"class\": \"IN\"\n" +
                "  },\n" +
                "  \"answers\": [\n" +
                "    {\n" +
                "      \"type\": \"A\",\n" +
                "      \"rdata\": \"127.0.0.62\",\n" +
                "      \"class\": \"IN\"\n" +
                "    }\n" +
                "  ],\n" +
                "  \"connection_info\": {\n" +
                "    \"protocol_name\": \"UDP\",\n" +
                "    \"direction\": \"Unknown\",\n" +
                "    \"direction_id\": 0\n" +
                "  },\n" +
                "  \"dst_endpoint\": {\n" +
                "    \"instance_uid\": \"rslvr-in-0000000000000000\",\n" +
                "    \"interface_uid\": \"rni-0000000000000000\"\n" +
                "  },\n" +
                "  \"severity_id\": 1,\n" +
                "  \"severity\": \"Informational\",\n" +
                "  \"class_name\": \"DNS Activity\",\n" +
                "  \"class_uid\": 4003,\n" +
                "  \"category_name\": \"Network Activity\",\n" +
                "  \"category_uid\": 4,\n" +
                "  \"rcode_id\": 0,\n" +
                "  \"rcode\": \"NoError\",\n" +
                "  \"activity_id\": 2,\n" +
                "  \"activity_name\": \"Response\",\n" +
                "  \"type_name\": \"DNS Activity: Response\",\n" +
                "  \"type_uid\": 400302,\n" +
                "  \"disposition\": \"No Action\",\n" +
                "  \"disposition_id\": 16,\n" +
                "  \"unmapped\": [\n" +
                "    [\n" +
                "      \"firewall_rule_group_id\",\n" +
                "      \"rslvr-frg-000000000000000\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"firewall_domain_list_id\",\n" +
                "      \"rslvr-fdl-0000000000000\"\n" +
                "    ]\n" +
                "  ]\n" +
                "}";
    }

    private String ocsfVpcflowDoc() {
        return "{\n" +
                "  \"metadata\": {\n" +
                "    \"product\": {\n" +
                "      \"version\": \"5\",\n" +
                "      \"name\": \"Amazon VPC\",\n" +
                "      \"feature\": {\n" +
                "        \"name\": \"Flowlogs\"\n" +
                "      },\n" +
                "      \"vendor_name\": \"AWS\"\n" +
                "    },\n" +
                "    \"profiles\": [\n" +
                "      \"cloud\",\n" +
                "      \"security_control\"\n" +
                "    ],\n" +
                "    \"version\": \"1.0.0-rc.2\"\n" +
                "  },\n" +
                "  \"cloud\": {\n" +
                "    \"account_uid\": \"123456789012\",\n" +
                "    \"region\": \"us-east-2\",\n" +
                "    \"zone\": \"use1-az1\",\n" +
                "    \"provider\": \"AWS\"\n" +
                "  },\n" +
                "  \"src_endpoint\": {\n" +
                "    \"port\": 56858,\n" +
                "    \"svc_name\": \"-\",\n" +
                "    \"ip\": \"1.2.3.4\",\n" +
                "    \"intermediate_ips\": null,\n" +
                "    \"interface_uid\": \"eni-000000000000000000\",\n" +
                "    \"vpc_uid\": \"vpc-00000000\",\n" +
                "    \"instance_uid\": \"i-000000000000000000\",\n" +
                "    \"subnet_uid\": \"subnet-000000000000000000\"\n" +
                "  },\n" +
                "  \"dst_endpoint\": {\n" +
                "    \"port\": 39938,\n" +
                "    \"svc_name\": \"-\",\n" +
                "    \"ip\": \"172.31.2.52\",\n" +
                "    \"intermediate_ips\": null,\n" +
                "    \"interface_uid\": null,\n" +
                "    \"vpc_uid\": null,\n" +
                "    \"instance_uid\": null,\n" +
                "    \"subnet_uid\": null\n" +
                "  },\n" +
                "  \"connection_info\": {\n" +
                "    \"protocol_num\": 6,\n" +
                "    \"tcp_flags\": 2,\n" +
                "    \"protocol_ver\": \"IPv4\",\n" +
                "    \"boundary_id\": 99,\n" +
                "    \"boundary\": \"-\",\n" +
                "    \"direction_id\": 2,\n" +
                "    \"direction\": \"Outbound\"\n" +
                "  },\n" +
                "  \"traffic\": {\n" +
                "    \"packets\": 1,\n" +
                "    \"bytes\": 50\n" +
                "  },\n" +
                "  \"time\": 1649721732000,\n" +
                "  \"start_time\": 1649721732000,\n" +
                "  \"end_time\": 1649721788000,\n" +
                "  \"status_code\": \"OK\",\n" +
                "  \"severity_id\": 1,\n" +
                "  \"severity\": \"Informational\",\n" +
                "  \"class_name\": \"Network Activity\",\n" +
                "  \"class_uid\": 4001,\n" +
                "  \"category_name\": \"Network Activity\",\n" +
                "  \"category_uid\": 4,\n" +
                "  \"activity_name\": \"Traffic\",\n" +
                "  \"activity_id\": 6,\n" +
                "  \"disposition\": \"Allowed\",\n" +
                "  \"disposition_id\": 1,\n" +
                "  \"type_uid\": 400106,\n" +
                "  \"type_name\": \"Network Activity: Traffic\",\n" +
                "  \"unmapped\": [\n" +
                "    [\n" +
                "      \"sublocation_id\",\n" +
                "      \"-\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"sublocation_type\",\n" +
                "      \"-\"\n" +
                "    ]\n" +
                "  ]\n" +
                "}";
    }

    private String ocsfCloudtrailDoc() {
        return "{\n" +
                "  \"metadata\": {\n" +
                "    \"product\": {\n" +
                "      \"version\": \"1.03\",\n" +
                "      \"name\": \"CloudTrail\",\n" +
                "      \"vendor_name\": \"AWS\",\n" +
                "      \"feature\": {\n" +
                "        \"name\": \"Management, Data, and Insights\"\n" +
                "      }\n" +
                "    },\n" +
                "    \"uid\": \"6f4ab5bd-2daa-4d00-be14-d92efEXAMPLE\",\n" +
                "    \"profiles\": [\n" +
                "      \"cloud\"\n" +
                "    ],\n" +
                "    \"version\": \"1.0.0-rc.2\"\n" +
                "  },\n" +
                "  \"time\": 1459524708000,\n" +
                "  \"cloud\": {\n" +
                "    \"region\": \"us-west-2\",\n" +
                "    \"provider\": \"AWS\"\n" +
                "  },\n" +
                "  \"api\": {\n" +
                "    \"response\": {\n" +
                "      \"error\": null,\n" +
                "      \"message\": null\n" +
                "    },\n" +
                "    \"operation\": \"CreateLoadBalancer\",\n" +
                "    \"version\": \"2015-12-01\",\n" +
                "    \"service\": {\n" +
                "      \"name\": \"elasticloadbalancing.amazonaws.com\"\n" +
                "    },\n" +
                "    \"request\": {\n" +
                "      \"uid\": \"b9960276-b9b2-11e3-8a13-f1ef1EXAMPLE\"\n" +
                "    }\n" +
                "  },\n" +
                "  \"resources\": null,\n" +
                "  \"actor\": {\n" +
                "    \"user\": {\n" +
                "      \"type\": \"IAMUser\",\n" +
                "      \"name\": \"Alice\",\n" +
                "      \"uid\": \"123456789012\",\n" +
                "      \"uuid\": \"arn:aws:iam::123456789012:user/Alice\",\n" +
                "      \"account_uid\": \"123456789012\",\n" +
                "      \"credential_uid\": \"AKIAIOSFODNN7EXAMPLE\"\n" +
                "    },\n" +
                "    \"session\": {\n" +
                "      \"created_time\": null,\n" +
                "      \"mfa\": null,\n" +
                "      \"issuer\": null\n" +
                "    },\n" +
                "    \"invoked_by\": null,\n" +
                "    \"idp\": {\n" +
                "      \"name\": null\n" +
                "    }\n" +
                "  },\n" +
                "  \"http_request\": {\n" +
                "    \"user_agent\": \"aws-cli/1.10.10 Python/2.7.9 Windows/7 botocore/1.4.1\"\n" +
                "  },\n" +
                "  \"src_endpoint\": {\n" +
                "    \"uid\": null,\n" +
                "    \"ip\": \"198.51.100.1\",\n" +
                "    \"domain\": null\n" +
                "  },\n" +
                "  \"class_name\": \"API Activity\",\n" +
                "  \"class_uid\": 3005,\n" +
                "  \"category_name\": \"Audit Activity\",\n" +
                "  \"category_uid\": 3,\n" +
                "  \"severity_id\": 1,\n" +
                "  \"severity\": \"Informational\",\n" +
                "  \"status\": \"Success\",\n" +
                "  \"status_id\": 1,\n" +
                "  \"activity_name\": \"Create\",\n" +
                "  \"activity_id\": 1,\n" +
                "  \"type_uid\": 300501,\n" +
                "  \"type_name\": \"API Activity: Create\",\n" +
                "  \"unmapped\": [\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].state.code\",\n" +
                "      \"provisioning\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].canonicalHostedZoneId\",\n" +
                "      \"Z2P70J7HTTTPLU\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].availabilityZones[].subnetId\",\n" +
                "      \"subnet-8360a9e7,subnet-b7d581c0\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].loadBalancerName\",\n" +
                "      \"my-load-balancer\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].type\",\n" +
                "      \"application\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].dNSName\",\n" +
                "      \"my-load-balancer-1836718677.us-west-2.elb.amazonaws.com\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"eventType\",\n" +
                "      \"AwsApiCall\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].vpcId\",\n" +
                "      \"vpc-3ac0fb5f\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].securityGroups[]\",\n" +
                "      \"sg-5943793c\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"requestParameters.subnets[]\",\n" +
                "      \"subnet-8360a9e7,subnet-b7d581c0\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"requestParameters.securityGroups[]\",\n" +
                "      \"sg-5943793c\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].scheme\",\n" +
                "      \"internet-facing\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].availabilityZones[].zoneName\",\n" +
                "      \"us-west-2a,us-west-2b\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"recipientAccountId\",\n" +
                "      \"123456789012\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].createdTime\",\n" +
                "      \"Apr 11, 2016 5:23:50 PM\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"responseElements.loadBalancers[].loadBalancerArn\",\n" +
                "      \"arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/my-load-balancer/ffcddace1759e1d0\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"requestParameters.scheme\",\n" +
                "      \"internet-facing\"\n" +
                "    ],\n" +
                "    [\n" +
                "      \"requestParameters.name\",\n" +
                "      \"my-load-balancer\"\n" +
                "    ]\n" +
                "  ]\n" +
                "}";
    }

    private String rawRoute53DnsMappings() {
        return "\"properties\": {\n" +
                "                \"account_id\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"answers\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"Class\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"Rdata\": {\n" +
                "                            \"type\": \"keyword\"\n" +
                "                        },\n" +
                "                        \"Type\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"firewall_domain_list_id\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"firewall_rule_action\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"firewall_rule_group_id\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"query_class\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"query_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"query_timestamp\": {\n" +
                "                    \"type\": \"date\"\n" +
                "                },\n" +
                "                \"query_type\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"rcode\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"region\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"srcaddr\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"srcids\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"resolver_endpoint\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"resolver_network_interface\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"srcport\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"transport\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"version\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"vpc_id\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                }\n" +
                "            }";
    }

    private String rawCloudtrailMappings() {
        return "\"properties\": {\n" +
                "                \"apiVersion\": {\n" +
                "                    \"type\": \"date\"\n" +
                "                },\n" +
                "                \"awsRegion\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"eventID\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"eventName\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"eventSource\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"eventTime\": {\n" +
                "                    \"type\": \"date\"\n" +
                "                },\n" +
                "                \"eventType\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"eventVersion\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"recipientAccountId\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"requestID\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"requestParameters\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"name\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"scheme\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"securityGroups\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"subnets\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"responseElements\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"loadBalancers\": {\n" +
                "                            \"properties\": {\n" +
                "                                \"availabilityZones\": {\n" +
                "                                    \"properties\": {\n" +
                "                                        \"subnetId\": {\n" +
                "                                            \"type\": \"text\",\n" +
                "                                            \"fields\": {\n" +
                "                                                \"keyword\": {\n" +
                "                                                    \"type\": \"keyword\",\n" +
                "                                                    \"ignore_above\": 256\n" +
                "                                                }\n" +
                "                                            }\n" +
                "                                        },\n" +
                "                                        \"zoneName\": {\n" +
                "                                            \"type\": \"text\",\n" +
                "                                            \"fields\": {\n" +
                "                                                \"keyword\": {\n" +
                "                                                    \"type\": \"keyword\",\n" +
                "                                                    \"ignore_above\": 256\n" +
                "                                                }\n" +
                "                                            }\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"canonicalHostedZoneId\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"createdTime\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"dNSName\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"loadBalancerArn\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"loadBalancerName\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"scheme\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"securityGroups\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"state\": {\n" +
                "                                    \"properties\": {\n" +
                "                                        \"code\": {\n" +
                "                                            \"type\": \"text\",\n" +
                "                                            \"fields\": {\n" +
                "                                                \"keyword\": {\n" +
                "                                                    \"type\": \"keyword\",\n" +
                "                                                    \"ignore_above\": 256\n" +
                "                                                }\n" +
                "                                            }\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"type\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"vpcId\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"sourceIPAddress\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"userAgent\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"userIdentity\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"accessKeyId\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"accountId\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"arn\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"principalId\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"type\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"userName\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                }\n" +
                "            }";
    }

    private String ocsfRoute53Mappings() {
        return "\"properties\": {\n" +
                "                \"activity_id\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"activity_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"answers\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"class\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"rdata\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"type\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"category_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"category_uid\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"class_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"class_uid\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"cloud\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"account_uid\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"provider\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"region\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"connection_info\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"direction\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"direction_id\": {\n" +
                "                            \"type\": \"long\"\n" +
                "                        },\n" +
                "                        \"protocol_name\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"disposition\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"disposition_id\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"dst_endpoint\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"instance_uid\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"interface_uid\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"metadata\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"product\": {\n" +
                "                            \"properties\": {\n" +
                "                                \"feature\": {\n" +
                "                                    \"properties\": {\n" +
                "                                        \"name\": {\n" +
                "                                            \"type\": \"text\",\n" +
                "                                            \"fields\": {\n" +
                "                                                \"keyword\": {\n" +
                "                                                    \"type\": \"keyword\",\n" +
                "                                                    \"ignore_above\": 256\n" +
                "                                                }\n" +
                "                                            }\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"name\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"vendor_name\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"version\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"profiles\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"version\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"queries\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"class\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"hostname\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"type\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"rcode\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"rcode_id\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"severity\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"severity_id\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"src_endpoint\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"ip\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"port\": {\n" +
                "                            \"type\": \"long\"\n" +
                "                        },\n" +
                "                        \"vpc_uid\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"time\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"type_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"type_uid\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"unmapped\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                }\n" +
                "            }";
    }

    private String ocsfVpcflowMappings() {
        return "\"properties\": {\n" +
                "                \"activity_id\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"activity_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"category_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"category_uid\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"class_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"class_uid\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"cloud\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"account_uid\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"provider\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"region\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"zone\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"connection_info\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"boundary\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"boundary_id\": {\n" +
                "                            \"type\": \"long\"\n" +
                "                        },\n" +
                "                        \"direction\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"direction_id\": {\n" +
                "                            \"type\": \"long\"\n" +
                "                        },\n" +
                "                        \"protocol_num\": {\n" +
                "                            \"type\": \"long\"\n" +
                "                        },\n" +
                "                        \"protocol_ver\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"tcp_flags\": {\n" +
                "                            \"type\": \"long\"\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"disposition\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"disposition_id\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"dst_endpoint\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"ip\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"port\": {\n" +
                "                            \"type\": \"long\"\n" +
                "                        },\n" +
                "                        \"svc_name\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"end_time\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"metadata\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"product\": {\n" +
                "                            \"properties\": {\n" +
                "                                \"feature\": {\n" +
                "                                    \"properties\": {\n" +
                "                                        \"name\": {\n" +
                "                                            \"type\": \"text\",\n" +
                "                                            \"fields\": {\n" +
                "                                                \"keyword\": {\n" +
                "                                                    \"type\": \"keyword\",\n" +
                "                                                    \"ignore_above\": 256\n" +
                "                                                }\n" +
                "                                            }\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"name\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"vendor_name\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"version\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"profiles\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"version\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"severity\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"severity_id\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"src_endpoint\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"instance_uid\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"interface_uid\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"ip\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"port\": {\n" +
                "                            \"type\": \"long\"\n" +
                "                        },\n" +
                "                        \"subnet_uid\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"svc_name\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"vpc_uid\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"start_time\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"status_code\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"time\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"traffic\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"bytes\": {\n" +
                "                            \"type\": \"long\"\n" +
                "                        },\n" +
                "                        \"packets\": {\n" +
                "                            \"type\": \"long\"\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"type_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"type_uid\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"unmapped\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                }\n" +
                "            }";
    }

    private String ocsfCloudtrailMappings() {
        return "\"properties\": {\n" +
                "                \"activity_id\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"activity_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"actor\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"idp\": {\n" +
                "                            \"type\": \"object\"\n" +
                "                        },\n" +
                "                        \"session\": {\n" +
                "                            \"type\": \"object\"\n" +
                "                        },\n" +
                "                        \"user\": {\n" +
                "                            \"properties\": {\n" +
                "                                \"account_uid\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"credential_uid\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"name\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"type\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"uid\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"uuid\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"api\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"operation\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"request\": {\n" +
                "                            \"properties\": {\n" +
                "                                \"uid\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"response\": {\n" +
                "                            \"type\": \"object\"\n" +
                "                        },\n" +
                "                        \"service\": {\n" +
                "                            \"properties\": {\n" +
                "                                \"name\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"version\": {\n" +
                "                            \"type\": \"date\"\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"category_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"category_uid\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"class_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"class_uid\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"cloud\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"provider\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"region\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"http_request\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"user_agent\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"metadata\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"product\": {\n" +
                "                            \"properties\": {\n" +
                "                                \"feature\": {\n" +
                "                                    \"properties\": {\n" +
                "                                        \"name\": {\n" +
                "                                            \"type\": \"text\",\n" +
                "                                            \"fields\": {\n" +
                "                                                \"keyword\": {\n" +
                "                                                    \"type\": \"keyword\",\n" +
                "                                                    \"ignore_above\": 256\n" +
                "                                                }\n" +
                "                                            }\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"name\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"vendor_name\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                },\n" +
                "                                \"version\": {\n" +
                "                                    \"type\": \"text\",\n" +
                "                                    \"fields\": {\n" +
                "                                        \"keyword\": {\n" +
                "                                            \"type\": \"keyword\",\n" +
                "                                            \"ignore_above\": 256\n" +
                "                                        }\n" +
                "                                    }\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"profiles\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"uid\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        },\n" +
                "                        \"version\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"severity\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"severity_id\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"src_endpoint\": {\n" +
                "                    \"properties\": {\n" +
                "                        \"ip\": {\n" +
                "                            \"type\": \"text\",\n" +
                "                            \"fields\": {\n" +
                "                                \"keyword\": {\n" +
                "                                    \"type\": \"keyword\",\n" +
                "                                    \"ignore_above\": 256\n" +
                "                                }\n" +
                "                            }\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"status\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"status_id\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"time\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"type_name\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"type_uid\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"unmapped\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                }\n" +
                "            }";
    }

    private String rawVpcFlowMappings() {
        return "\"properties\": {\n" +
                "                \"account_id\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"action\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"az_id\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"bytes\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"dstaddr\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"dstport\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"end\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"flow_direction\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"instance_id\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"interface_id\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"log_status\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"packets\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"pkt_dst_aws_service\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"pkt_dstaddr\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"pkt_src_aws_service\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"pkt_srcaddr\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"protocol\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"region\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"srcaddr\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"srcport\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"start\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"sublocation_id\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"sublocation_type\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"subnet_id\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"tcp_flags\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"traffic_path\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"type\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                },\n" +
                "                \"version\": {\n" +
                "                    \"type\": \"long\"\n" +
                "                },\n" +
                "                \"vpc_id\": {\n" +
                "                    \"type\": \"text\",\n" +
                "                    \"fields\": {\n" +
                "                        \"keyword\": {\n" +
                "                            \"type\": \"keyword\",\n" +
                "                            \"ignore_above\": 256\n" +
                "                        }\n" +
                "                    }\n" +
                "                }\n" +
                "            }";
    }
}