/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.opensearch.Version;
import org.opensearch.action.admin.indices.template.put.PutComponentTemplateAction;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.cluster.metadata.ComponentTemplate;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.model.CreateMappingResult;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IndexTemplateManagerTemplateResolutionTests extends OpenSearchTestCase {

    private static IndexMetadata index(String name, String indexAlias) {
        return IndexMetadata.builder(name)
                .settings(settings(Version.CURRENT))
                .numberOfShards(1)
                .numberOfReplicas(0)
                .putAlias(AliasMetadata.builder(indexAlias).writeIndex(true).build())
                .build();
    }

    @SuppressWarnings("unchecked")
    public void testComponentTemplateAttachedToTemplateOfWriteIndex() throws Exception {
        String rcxComponent = IndexTemplateUtils.computeComponentTemplateName("detector-rcx");
        String rcxbComponent = IndexTemplateUtils.computeComponentTemplateName("detector-rcxb");
        ComponentTemplate componentTemplate = new ComponentTemplate(
                new Template(null, new CompressedXContent("{\"properties\":{}}"), null), 0L, null
        );
        Metadata metadata = Metadata.builder()
                .put(index("rcx-000001", "detector-rcx"), false)
                .put(index("rcxb-000001", "detector-rcxb"), false)
                .put(rcxComponent, componentTemplate)
                .put("rcx", new ComposableIndexTemplate(List.of("rcx-*", "detector-rcx*"), null, List.of(rcxComponent), 0L, null, null))
                .put("rcxb", new ComposableIndexTemplate(List.of("rcxb-*"), null, List.of(), 0L, null, null))
                .build();
        ClusterState state = ClusterState.builder(ClusterName.DEFAULT).metadata(metadata).build();

        ClusterService clusterService = mock(ClusterService.class);
        when(clusterService.state()).thenReturn(state);
        Client client = mock(Client.class);
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();
        doAnswer(invocation -> {
            ((ActionListener<AcknowledgedResponse>) invocation.getArgument(2)).onResponse(new AcknowledgedResponse(true));
            return null;
        }).when(client).execute(eq(PutComponentTemplateAction.INSTANCE), any(), any());
        doAnswer(invocation -> {
            putIndexTemplateRequests.add(invocation.getArgument(1));
            ((ActionListener<AcknowledgedResponse>) invocation.getArgument(2)).onResponse(new AcknowledgedResponse(true));
            return null;
        }).when(client).execute(eq(PutComposableIndexTemplateAction.INSTANCE), any(), any());

        IndexTemplateManager indexTemplateManager = new IndexTemplateManager(
                client,
                clusterService,
                new IndexNameExpressionResolver(new ThreadContext(Settings.EMPTY)),
                NamedXContentRegistry.EMPTY
        );
        Map<String, Object> mappings = Map.of("properties", Map.of(
                "destination.ip", Map.of("type", "alias", "path", "rcxb.dst"),
                "rcxb.dst", Map.of("type", "ip")
        ));
        PlainActionFuture<AcknowledgedResponse> future = new PlainActionFuture<>();
        indexTemplateManager.upsertIndexTemplateWithAliasMappings(
                "detector-rcxb",
                List.of(new CreateMappingResult(new AcknowledgedResponse(true), "rcxb-000001", mappings)),
                future
        );

        assertTrue(future.get().isAcknowledged());
        assertEquals(1, putIndexTemplateRequests.size());
        PutComposableIndexTemplateAction.Request request = putIndexTemplateRequests.get(0);
        assertEquals("rcxb", request.name());
        assertEquals(List.of(rcxbComponent), request.indexTemplate().composedOf());
        assertEquals(List.of("rcxb-*"), request.indexTemplate().indexPatterns());
    }
}
