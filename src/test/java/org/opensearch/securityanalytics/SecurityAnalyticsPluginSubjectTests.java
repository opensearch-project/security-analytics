/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.resources.RecordingClient;
import org.opensearch.securityanalytics.resources.SecurityAnalyticsPluginClient;
import org.opensearch.securityanalytics.resources.TestPluginSubject;
import org.opensearch.test.OpenSearchTestCase;

/** Tests that the subject core assigns is the one the plugin's own client runs actions as. */
public class SecurityAnalyticsPluginSubjectTests extends OpenSearchTestCase {

    public void testAssignSubjectSetsTheSubjectOfThePluginClient() {
        try (RecordingClient client = new RecordingClient(getTestName())) {
            SecurityAnalyticsPlugin plugin = new SecurityAnalyticsPlugin();
            plugin.pluginClient = new SecurityAnalyticsPluginClient(client);

            plugin.assignSubject(new TestPluginSubject(client.threadPool().getThreadContext()));
            plugin.pluginClient.execute(SearchAction.INSTANCE, new SearchRequest(), ActionListener.wrap(r -> {}, e -> {}));

            assertEquals(1, client.calls().size());
            assertEquals(TestPluginSubject.NAME, client.calls().get(0).subject());
        }
    }
}
