/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting;

import org.opensearch.action.admin.cluster.node.info.NodeInfo;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.opensearch.action.admin.cluster.node.info.PluginsAndModules;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.securityanalytics.Tokens;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SecurityAnalyticsPluginIT extends SecurityAnalyticsIntegTest {

    public void testBothSecurityAndAlertingPluginsAreLoaded() {
        final NodesInfoRequest nodesInfoRequest = new NodesInfoRequest();
        nodesInfoRequest.addMetric(NodesInfoRequest.Metric.PLUGINS.metricName());
        final NodesInfoResponse nodesInfoResponse = client().admin().cluster().nodesInfo(nodesInfoRequest)
                .actionGet();
        final List<PluginInfo> pluginInfos = nodesInfoResponse.getNodes().stream()
                .flatMap((Function<NodeInfo, Stream<PluginInfo>>) nodeInfo -> nodeInfo.getInfo(PluginsAndModules.class)
                        .getPluginInfos().stream()).collect(Collectors.toList());
        assertTrue(pluginInfos.stream().anyMatch(pluginInfo -> pluginInfo.getName()
                .equals(Tokens.OPENSEARCH_SECURITY_ANALYTICS)));
        assertTrue(pluginInfos.stream().anyMatch(pluginInfo -> pluginInfo.getName()
                .equals(Tokens.OPENSEARCH_ALERTING)));
        pluginInfos.stream().filter(x -> x.getName().equals(Tokens.OPENSEARCH_ALERTING)).forEach(x -> logger.info(x.getDescription()));
    }

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