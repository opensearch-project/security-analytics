/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutionException;

import org.mockito.ArgumentCaptor;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

public class RuleTopicIndicesTests extends OpenSearchTestCase {

    public void testInitRuleTopicIndexTemplateUsesLogTypeMetadata()
            throws ExecutionException, InterruptedException, IOException {
        Client client = mock(Client.class);
        ClusterService clusterService = mock(ClusterService.class);
        LogTypeService logTypeService = mock(LogTypeService.class);
        RuleTopicIndices ruleTopicIndices = new RuleTopicIndices(client, clusterService, logTypeService);

        List<String> logTypes = List.of("apache_access", "windows");
        doAnswer(invocation -> {
            ActionListener<List<String>> listener = invocation.getArgument(0);
            listener.onResponse(logTypes);
            return null;
        }).when(logTypeService).getAllLogTypesMetadata(any());

        ArgumentCaptor<PutComposableIndexTemplateAction.Request> requestCaptor =
                ArgumentCaptor.forClass(PutComposableIndexTemplateAction.Request.class);
        doAnswer(invocation -> {
            ActionListener<AcknowledgedResponse> listener = invocation.getArgument(2);
            listener.onResponse(new AcknowledgedResponse(true));
            return null;
        }).when(client).execute(eq(PutComposableIndexTemplateAction.INSTANCE), requestCaptor.capture(), any());

        PlainActionFuture<AcknowledgedResponse> future = new PlainActionFuture<>();
        ruleTopicIndices.initRuleTopicIndexTemplate(future);
        future.get();

        ComposableIndexTemplate template = requestCaptor.getValue().indexTemplate();
        List<String> indexPatterns = template.indexPatterns();

        assertEquals(2, indexPatterns.size());
        assertTrue(indexPatterns.contains(DetectorMonitorConfig.getRuleIndex("apache_access") + "*"));
        assertTrue(indexPatterns.contains(DetectorMonitorConfig.getRuleIndex("windows") + "*"));
    }
}

