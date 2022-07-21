/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.SecurityAnalyticsIntegTestCase;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

public class RuleRestApiIT extends SecurityAnalyticsIntegTestCase {

    public void testOnboardRulesWithWindowsTopicAsFilter() throws IOException {
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULES_BASE_URI, Collections.singletonMap("rule_topic", "windows"),
                new StringEntity("{}", ContentType.APPLICATION_JSON));

        Assert.assertEquals("Onboard Rules failed", RestStatus.CREATED.getStatus(), response.getStatusLine().getStatusCode());
        Map<String, Object> responseMap = entityAsMap(response);

        long ruleCount = Long.parseLong(responseMap.get("rule_count").toString());
        Assert.assertEquals(1579L, ruleCount);
    }

    public void testOnboardRulesWithMacosTopicAsFilter() throws IOException {
        Response response = makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULES_BASE_URI, Collections.singletonMap("rule_topic", "macos"),
                new StringEntity("{}", ContentType.APPLICATION_JSON));

        Assert.assertEquals("Onboard Rules failed", RestStatus.CREATED.getStatus(), response.getStatusLine().getStatusCode());
        Map<String, Object> responseMap = entityAsMap(response);

        long ruleCount = Long.parseLong(responseMap.get("rule_count").toString());
        Assert.assertEquals(30L, ruleCount);
    }

    public void testOnboardRulesWithNoTopic() {
        ResponseException exception = assertThrows(ResponseException.class, () -> {
            makeRequest(client(), "POST", SecurityAnalyticsPlugin.RULES_BASE_URI, Collections.emptyMap(),
                    new StringEntity("{}", ContentType.APPLICATION_JSON));
        });
        assertTrue(exception.getMessage().contains("rule_topic is empty"));
    }
}