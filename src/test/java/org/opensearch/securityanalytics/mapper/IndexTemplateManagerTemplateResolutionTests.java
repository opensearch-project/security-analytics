/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.mapper;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
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

    private static final String RCX_COMPONENT = IndexTemplateUtils.computeComponentTemplateName("detector-rcx");
    private static final String RCXB_COMPONENT = IndexTemplateUtils.computeComponentTemplateName("detector-rcxb");
    private static final Map<String, Object> RCXB_MAPPINGS = Map.of("properties", Map.of(
            "destination.ip", Map.of("type", "alias", "path", "rcxb.dst"),
            "rcxb.dst", Map.of("type", "ip")
    ));

    private static IndexMetadata index(String name, String indexAlias, Boolean writeIndex, long creationDate) {
        return IndexMetadata.builder(name)
                .settings(settings(Version.CURRENT).put(IndexMetadata.SETTING_CREATION_DATE, creationDate))
                .numberOfShards(1)
                .numberOfReplicas(0)
                .putAlias(AliasMetadata.builder(indexAlias).writeIndex(writeIndex).build())
                .build();
    }

    private static Metadata.Builder rcxTemplateWithIndexAliasPattern() throws Exception {
        ComponentTemplate componentTemplate = new ComponentTemplate(
                new Template(null, new CompressedXContent("{\"properties\":{}}"), null), 0L, null
        );
        return Metadata.builder()
                .put(index("rcx-000001", "detector-rcx", true, 1L), false)
                .put(RCX_COMPONENT, componentTemplate)
                .put("rcx", new ComposableIndexTemplate(List.of("rcx-*", "detector-rcx*"), null, List.of(RCX_COMPONENT), 0L, null, null));
    }

    @SuppressWarnings("unchecked")
    private static AcknowledgedResponse upsert(
            Metadata metadata,
            String concreteIndex,
            List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests
    ) throws Exception {
        ClusterState state = ClusterState.builder(ClusterName.DEFAULT).metadata(metadata).build();
        ClusterService clusterService = mock(ClusterService.class);
        when(clusterService.state()).thenReturn(state);
        Client client = mock(Client.class);
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
        PlainActionFuture<AcknowledgedResponse> future = new PlainActionFuture<>();
        indexTemplateManager.upsertIndexTemplateWithAliasMappings(
                "detector-rcxb",
                List.of(new CreateMappingResult(new AcknowledgedResponse(true), concreteIndex, RCXB_MAPPINGS)),
                future
        );
        return future.get();
    }

    public void testComponentTemplateAttachedToTemplateOfWriteIndex() throws Exception {
        Metadata metadata = rcxTemplateWithIndexAliasPattern()
                .put(index("rcxb-000001", "detector-rcxb", true, 1L), false)
                .put("rcxb", new ComposableIndexTemplate(List.of("rcxb-*"), null, List.of(), 0L, null, null))
                .build();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        assertTrue(upsert(metadata, "rcxb-000001", putIndexTemplateRequests).isAcknowledged());
        assertEquals(1, putIndexTemplateRequests.size());
        PutComposableIndexTemplateAction.Request request = putIndexTemplateRequests.get(0);
        assertEquals("rcxb", request.name());
        assertEquals(List.of(RCXB_COMPONENT), request.indexTemplate().composedOf());
        assertEquals(List.of("rcxb-*"), request.indexTemplate().indexPatterns());
    }

    public void testComponentTemplateAttachedToTemplateOfNewestIndexWithoutWriteIndex() throws Exception {
        Metadata metadata = rcxTemplateWithIndexAliasPattern()
                .put(index("rcxb-2026.10.08", "detector-rcxb", null, 1L), false)
                .put(index("rcxb-2026.10.09", "detector-rcxb", null, 2L), false)
                .put("rcxb", new ComposableIndexTemplate(List.of("rcxb-*"), null, List.of(), 0L, null, null))
                .build();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        assertTrue(upsert(metadata, "rcxb-2026.10.09", putIndexTemplateRequests).isAcknowledged());
        assertEquals(1, putIndexTemplateRequests.size());
        PutComposableIndexTemplateAction.Request request = putIndexTemplateRequests.get(0);
        assertEquals("rcxb", request.name());
        assertEquals(List.of(RCXB_COMPONENT), request.indexTemplate().composedOf());
        assertEquals(List.of("rcxb-*"), request.indexTemplate().indexPatterns());
    }

    public void testIndexAliasNotResolvedByNameWhenBackingIndexMatchesNoTemplate() throws Exception {
        Metadata metadata = rcxTemplateWithIndexAliasPattern()
                .put(index("unmatched-000001", "detector-rcxb", true, 1L), false)
                .build();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        ExecutionException e = expectThrows(
                ExecutionException.class,
                () -> upsert(metadata, "unmatched-000001", putIndexTemplateRequests)
        );
        assertTrue(e.getMessage(), e.getMessage().contains("Found conflicting template: [rcx]"));
        assertTrue(putIndexTemplateRequests.isEmpty());
    }
}
