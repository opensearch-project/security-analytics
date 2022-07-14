/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.SigmaLogsourceError;
import org.opensearch.test.OpenSearchTestCase;

import java.util.HashMap;
import java.util.Map;

public class SigmaLogSourceTests extends OpenSearchTestCase {

    public void testSigmaLogSourceFromDict() throws SigmaLogsourceError {
        Map<String, Object> logSourceMap = new HashMap<>();
        logSourceMap.put("category", "category-id");
        logSourceMap.put("product", "product-id");
        logSourceMap.put("service", "service-id");

        SigmaLogSource actualLogSource = SigmaLogSource.fromDict(logSourceMap);
        SigmaLogSource expectedLogSource = new SigmaLogSource("product-id", "category-id", "service-id");

        Assert.assertEquals(expectedLogSource.getProduct(), actualLogSource.getProduct());
        Assert.assertEquals(expectedLogSource.getCategory(), actualLogSource.getCategory());
        Assert.assertEquals(expectedLogSource.getService(), actualLogSource.getService());
    }

    public void testSigmaLogSourceFromDictNoCategory() throws SigmaLogsourceError {
        Map<String, Object> logSourceMap = new HashMap<>();
        logSourceMap.put("product", "product-id");
        logSourceMap.put("service", "service-id");

        SigmaLogSource actualLogSource = SigmaLogSource.fromDict(logSourceMap);
        SigmaLogSource expectedLogSource = new SigmaLogSource("product-id", null, "service-id");

        Assert.assertEquals(expectedLogSource.getProduct(), actualLogSource.getProduct());
        Assert.assertEquals(expectedLogSource.getService(), actualLogSource.getService());
    }

    public void testSigmaLogSourceFromDictNoProduct() throws SigmaLogsourceError {
        Map<String, Object> logSourceMap = new HashMap<>();
        logSourceMap.put("category", "category-id");
        logSourceMap.put("service", "service-id");

        SigmaLogSource actualLogSource = SigmaLogSource.fromDict(logSourceMap);
        SigmaLogSource expectedLogSource = new SigmaLogSource(null, "category-id", "service-id");

        Assert.assertEquals(expectedLogSource.getCategory(), actualLogSource.getCategory());
        Assert.assertEquals(expectedLogSource.getService(), actualLogSource.getService());
    }

    public void testSigmaLogSourceFromDictNoService() throws SigmaLogsourceError {
        Map<String, Object> logSourceMap = new HashMap<>();
        logSourceMap.put("category", "category-id");
        logSourceMap.put("product", "product-id");

        SigmaLogSource actualLogSource = SigmaLogSource.fromDict(logSourceMap);
        SigmaLogSource expectedLogSource = new SigmaLogSource("product-id", "category-id", null);

        Assert.assertEquals(expectedLogSource.getProduct(), actualLogSource.getProduct());
        Assert.assertEquals(expectedLogSource.getCategory(), actualLogSource.getCategory());
    }

    public void testSigmaLogSourceEmpty() {
        Exception exception = assertThrows(SigmaLogsourceError.class, () -> {
            new SigmaLogSource(null, null, null);
        });

        String expectedMessage = "Log source can't be empty";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }
}