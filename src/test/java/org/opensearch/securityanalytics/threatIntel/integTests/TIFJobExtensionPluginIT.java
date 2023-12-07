/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.securityanalytics.threatIntel.integTests;

import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.SecurityAnalyticsRestTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class TIFJobExtensionPluginIT extends SecurityAnalyticsRestTestCase {
    public void testPluginsAreInstalled() throws IOException {
        Request request = new Request("GET", "/_cat/plugins?s=component&h=name,component,version,description&format=json");
        Response response = client().performRequest(request);
        List<Object> pluginsList = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY,
                LoggingDeprecationHandler.INSTANCE, response.getEntity().getContent()).list();
        Assert.assertTrue(pluginsList.stream().map(o -> (Map<String, Object>) o).anyMatch(plugin -> plugin.get("component")
                .equals("opensearch-job-scheduler")));
    }
}
