/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation;

import org.junit.Assert;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.opensearch.securityanalytics.model.CorrelationRule;

import java.io.IOException;
import java.util.Collections;

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
}