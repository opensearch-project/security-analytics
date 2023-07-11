/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation;

import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.model.CorrelationRule;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import static org.opensearch.securityanalytics.TestHelpers.randomCorrelationRule;

public class CorrelationEngineRuleRestApiIT extends SecurityAnalyticsRestTestCase {

    public void testCreateCorrelationRule() throws IOException {
        CorrelationRule rule = randomCorrelationRule("custom-rule");
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, Collections.emptyMap(), toHttpEntity(rule));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
    }

    public void testCreateCorrelationRuleWithInvalidName() {
        CorrelationRule rule = randomCorrelationRule("");
        Exception exception = assertThrows(ResponseException.class, () -> {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, Collections.emptyMap(), toHttpEntity(rule));
        });
        String expectedMessage = "{\"error\":{\"root_cause\":[{\"type\":\"action_request_validation_exception\",\"reason\":\"Validation Failed: \"}],\"type\":\"action_request_validation_exception\",\"reason\":\"Validation Failed: \"},\"status\":400}";
        String actualMessage = exception.getMessage();
        Assert.assertTrue(actualMessage.contains(expectedMessage));
    }

    @SuppressWarnings("unchecked")
    public void testUpdateCorrelationRule() throws IOException {
        CorrelationRule rule = randomCorrelationRule("custom-rule");
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, Collections.emptyMap(), toHttpEntity(rule));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseMap = responseAsMap(response);
        Assert.assertEquals("custom-rule", ((Map<String, Object>) responseMap.get("rule")).get("name"));

        String id = responseMap.get("_id").toString();

        rule = randomCorrelationRule("custom-updated-rule");
        response = makeRequest(client(), "PUT", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/" + id, Collections.emptyMap(), toHttpEntity(rule));
        Assert.assertEquals(200, response.getStatusLine().getStatusCode());
        responseMap = responseAsMap(response);
        Assert.assertEquals("custom-updated-rule", ((Map<String, Object>) responseMap.get("rule")).get("name"));
    }

    @SuppressWarnings("unchecked")
    public void testDeleteCorrelationRule() throws IOException {
        CorrelationRule rule = randomCorrelationRule("custom-rule");
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, Collections.emptyMap(), toHttpEntity(rule));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseMap = responseAsMap(response);
        Assert.assertEquals("custom-rule", ((Map<String, Object>) responseMap.get("rule")).get("name"));
        String id = responseMap.get("_id").toString();

        String request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", Collections.emptyMap(), new StringEntity(request), new BasicHeader("Content-type", "application/json"));
        responseMap = responseAsMap(response);
        Assert.assertEquals(1, Integer.parseInt(((Map<String, Object>) ((Map<String, Object>) responseMap.get("hits")).get("total")).get("value").toString()));

        response = makeRequest(client(), "DELETE", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/" + id, Collections.emptyMap(), null);
        Assert.assertEquals(200, response.getStatusLine().getStatusCode());

        request = "{\n" +
                "   \"query\" : {\n" +
                "     \"match_all\":{\n" +
                "     }\n" +
                "   }\n" +
                "}";
        response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", Collections.emptyMap(), new StringEntity(request), new BasicHeader("Content-type", "application/json"));
        responseMap = responseAsMap(response);
        Assert.assertEquals(0, Integer.parseInt(((Map<String, Object>) ((Map<String, Object>) responseMap.get("hits")).get("total")).get("value").toString()));
    }

    @SuppressWarnings("unchecked")
    public void testSearchCorrelationRule() throws IOException {
        CorrelationRule rule = randomCorrelationRule("custom-rule");
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI, Collections.emptyMap(), toHttpEntity(rule));
        Assert.assertEquals(201, response.getStatusLine().getStatusCode());
        Map<String, Object> responseMap = responseAsMap(response);
        Assert.assertEquals("custom-rule", ((Map<String, Object>) responseMap.get("rule")).get("name"));

        String request = "{\n" +
                "  \"query\": {\n" +
                "    \"nested\": {\n" +
                "      \"path\": \"correlate\",\n" +
                "      \"query\": {\n" +
                "        \"bool\": {\n" +
                "          \"must\": [\n" +
                "            { \"match\": {\"correlate.category\": \"network\"}}\n" +
                "          ]\n" +
                "        }\n" +
                "      }\n" +
                "    }\n" +
                "  }\n" +
                "}";
        response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.CORRELATION_RULES_BASE_URI + "/_search", Collections.emptyMap(), new StringEntity(request), new BasicHeader("Content-type", "application/json"));
        responseMap = responseAsMap(response);
        Assert.assertEquals(1, Integer.parseInt(((Map<String, Object>) ((Map<String, Object>) responseMap.get("hits")).get("total")).get("value").toString()));
    }
}