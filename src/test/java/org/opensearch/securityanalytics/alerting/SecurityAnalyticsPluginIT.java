/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting;

import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;

import java.util.Map;

public class SecurityAnalyticsPluginIT extends SecurityAnalyticsIntegTest {

    public void testAlertingPluginBasic() throws Exception {
        createIndex("testing");
        assertTrue(indexExists("testing"));
        final IndexResponse idxResponse = index("testing", "document", "1", Map.of("a", 1, "b", 2));
        assertEquals("1", idxResponse.getId());
        assertEquals("testing", idxResponse.getIndex());
        logger.error(idxResponse.getResult());
        GetResponse response = client().get(new GetRequest().index("testing").id("1").routing("_nodes/plugins")).get();
        logger.info(response.getSourceAsMap());
    }

    public void testMethodsAlertingPluginREST() throws Exception {
        createIndex("accounts");
        assertTrue(indexExists("accounts"));
        // GET /
        assertEquals(200, GET("/").getStatusLine().getStatusCode());
        // GET _cluster/settings?include_defaults=true
        assertEquals(200, GET("_cluster/settings").getStatusLine().getStatusCode());
        // GET _plugins/_alerting/stats
        assertEquals(200, GET("_plugins/_alerting/stats").getStatusLine().getStatusCode());
        // GET _plugins/_alerting/monitors/alerts
        assertEquals(200, GET("_plugins/_alerting/monitors/alerts").getStatusLine().getStatusCode());
        // POST _plugins/_alerting/monitors
        assertEquals(201, POST("_plugins/_alerting/monitors", ExampleAlertingJSON.CREATE_MONITOR_2).getStatusLine().getStatusCode());
        // GET _plugins/_alerting/monitors/_search
        assertEquals(200, GET("_plugins/_alerting/monitors/_search", ExampleAlertingJSON.SEARCH_MONITOR_1).getStatusLine().getStatusCode());
    }

    public void testMethodsSAPPluginREST() throws Exception {
        createIndex("accounts");
        assertTrue(indexExists("accounts"));
        // GET /
        //assertEquals(200, GET("/").getStatusLine().getStatusCode());
        // GET _cluster/settings?include_defaults=true
        //  assertEquals(200, GET("_cluster/settings").getStatusLine().getStatusCode());
        // GET _plugins/_alerting/stats
        // assertEquals(200, GET("_plugins/_security_analytics/stats").getStatusLine().getStatusCode());
        // GET _plugins/_alerting/monitors/alerts
        //assertEquals(200, GET("_plugins/_alerting/monitors/alerts").getStatusLine().getStatusCode());
        // POST _plugins/_alerting/monitors
        //assertEquals(201, POST("_plugins/_security_analytics/monitors", ExampleAlertingJSON.CREATE_MONITOR_2).getStatusLine().getStatusCode());
        // GET _plugins/_alerting/monitors/_search
        //assertEquals(200, GET("_plugins/_alerting/monitors/_search", ExampleAlertingJSON.SEARCH_MONITOR_1).getStatusLine().getStatusCode());
    }
}