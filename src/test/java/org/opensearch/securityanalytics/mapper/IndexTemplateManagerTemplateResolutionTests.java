/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
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

    private static AcknowledgedResponse upsert(
            Metadata metadata,
            String concreteIndex,
            List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests
    ) throws Exception {
        return upsert(metadata, "detector-rcxb", concreteIndex, new ArrayList<>(), putIndexTemplateRequests);
    }

    @SuppressWarnings("unchecked")
    private static AcknowledgedResponse upsert(
            Metadata metadata,
            String indexName,
            String concreteIndex,
            List<PutComponentTemplateAction.Request> putComponentTemplateRequests,
            List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests
    ) throws Exception {
        ClusterState state = ClusterState.builder(ClusterName.DEFAULT).metadata(metadata).build();
        ClusterService clusterService = mock(ClusterService.class);
        when(clusterService.state()).thenReturn(state);
        Client client = mock(Client.class);
        doAnswer(invocation -> {
            putComponentTemplateRequests.add(invocation.getArgument(1));
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
                indexName,
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
        List<PutComponentTemplateAction.Request> putComponentTemplateRequests = new ArrayList<>();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        assertTrue(upsert(metadata, "detector-rcxb", "unmatched-000001", putComponentTemplateRequests, putIndexTemplateRequests)
                .isAcknowledged());
        assertEquals(1, putComponentTemplateRequests.size());
        assertEquals(RCXB_COMPONENT, putComponentTemplateRequests.get(0).name());
        assertTrue(putIndexTemplateRequests.isEmpty());
    }

    public void testIndexAliasSkipsIndexTemplateWhenNoTemplateExists() throws Exception {
        Metadata metadata = Metadata.builder()
                .put(index("unmatched-000001", "detector-rcxb", true, 1L), false)
                .build();
        List<PutComponentTemplateAction.Request> putComponentTemplateRequests = new ArrayList<>();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        assertTrue(upsert(metadata, "detector-rcxb", "unmatched-000001", putComponentTemplateRequests, putIndexTemplateRequests)
                .isAcknowledged());
        assertEquals(1, putComponentTemplateRequests.size());
        assertTrue(putIndexTemplateRequests.isEmpty());
    }

    public void testIndexAliasCreatesSaTemplateWhenBackingIndexMatchesIndexAliasName() throws Exception {
        Metadata metadata = Metadata.builder()
                .put(index("logs-000001", "logs", false, 1L), false)
                .put(index("logs-000002", "logs", true, 2L), false)
                .build();
        List<PutComponentTemplateAction.Request> putComponentTemplateRequests = new ArrayList<>();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        assertTrue(upsert(metadata, "logs", "logs-000002", putComponentTemplateRequests, putIndexTemplateRequests).isAcknowledged());
        String logsComponent = IndexTemplateUtils.computeComponentTemplateName("logs");
        assertEquals(1, putComponentTemplateRequests.size());
        assertEquals(logsComponent, putComponentTemplateRequests.get(0).name());
        assertEquals(1, putIndexTemplateRequests.size());
        PutComposableIndexTemplateAction.Request request = putIndexTemplateRequests.get(0);
        assertEquals(IndexTemplateUtils.computeIndexTemplateName("logs"), request.name());
        assertTrue(request.create());
        assertEquals(List.of("logs*"), request.indexTemplate().indexPatterns());
        assertEquals(List.of(logsComponent), request.indexTemplate().composedOf());
    }

    public void testIndexAliasFailsOnSaTemplateOfAnotherIndexAliasMatchingBackingIndex() throws Exception {
        String logsTemplate = IndexTemplateUtils.computeIndexTemplateName("logs");
        Metadata metadata = Metadata.builder()
                .put(index("logs-app-000001", "logs-app", true, 1L), false)
                .put(logsTemplate, new ComposableIndexTemplate(
                        List.of("logs*"), null, List.of(IndexTemplateUtils.computeComponentTemplateName("logs")), null, null, null
                ))
                .build();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        ExecutionException e = expectThrows(
                ExecutionException.class,
                () -> upsert(metadata, "logs-app", "logs-app-000001", new ArrayList<>(), putIndexTemplateRequests)
        );
        assertTrue(e.getMessage(), e.getMessage().contains("Index template [" + logsTemplate + "] was created for another input"));
        assertTrue(putIndexTemplateRequests.isEmpty());
    }

    public void testIndexAliasFailsOnConflictingSaTemplateOfAnotherIndexAlias() throws Exception {
        String logsAppTemplate = IndexTemplateUtils.computeIndexTemplateName("logs-app");
        Metadata metadata = Metadata.builder()
                .put(index("logs-000001", "logs", true, 1L), false)
                .put(logsAppTemplate, new ComposableIndexTemplate(
                        List.of("logs-app*"), null, List.of(IndexTemplateUtils.computeComponentTemplateName("logs-app")), null, null, null
                ))
                .build();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        ExecutionException e = expectThrows(
                ExecutionException.class,
                () -> upsert(metadata, "logs", "logs-000001", new ArrayList<>(), putIndexTemplateRequests)
        );
        assertTrue(e.getMessage(), e.getMessage().contains("Index template [" + logsAppTemplate + "] was created for another input"));
        assertTrue(putIndexTemplateRequests.isEmpty());
    }

    public void testIndexAliasSkipsIndexTemplateWhenBackingIndexDoesNotMatchIndexAliasName() throws Exception {
        Metadata metadata = Metadata.builder()
                .put(index("x-000001", "detector-x", true, 1L), false)
                .build();
        List<PutComponentTemplateAction.Request> putComponentTemplateRequests = new ArrayList<>();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        assertTrue(upsert(metadata, "detector-x", "x-000001", putComponentTemplateRequests, putIndexTemplateRequests).isAcknowledged());
        assertEquals(1, putComponentTemplateRequests.size());
        assertEquals(IndexTemplateUtils.computeComponentTemplateName("detector-x"), putComponentTemplateRequests.get(0).name());
        assertTrue(putIndexTemplateRequests.isEmpty());
    }

    public void testIndexAliasRenamedBackingIndexAttachedToNewTemplate() throws Exception {
        String xComponent = IndexTemplateUtils.computeComponentTemplateName("detector-x");
        ComponentTemplate componentTemplate = new ComponentTemplate(
                new Template(null, new CompressedXContent("{\"properties\":{}}"), null), 0L, null
        );
        Metadata metadata = Metadata.builder()
                .put(index("x-new-000001", "detector-x", true, 1L), false)
                .put(xComponent, componentTemplate)
                .put("x-old", new ComposableIndexTemplate(List.of("x-old-*", "detector-x*"), null, List.of(xComponent), 0L, null, null))
                .put("x-new", new ComposableIndexTemplate(List.of("x-new-*"), null, List.of(), 0L, null, null))
                .build();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        assertTrue(upsert(metadata, "detector-x", "x-new-000001", new ArrayList<>(), putIndexTemplateRequests).isAcknowledged());
        assertEquals(1, putIndexTemplateRequests.size());
        PutComposableIndexTemplateAction.Request request = putIndexTemplateRequests.get(0);
        assertEquals("x-new", request.name());
        assertEquals(List.of(xComponent), request.indexTemplate().composedOf());
        assertEquals(List.of("x-new-*"), request.indexTemplate().indexPatterns());
    }

    public void testIndexPatternResolvedByInputNameBeforeNewestIndex() throws Exception {
        Metadata metadata = Metadata.builder()
                .put(index("logs-a-000001", "unrelated", null, 1L), false)
                .put(index("logs-b-000001", "unrelated", null, 2L), false)
                .put("logs", new ComposableIndexTemplate(List.of("logs-*"), null, List.of(), 1L, null, null))
                .put("logs-b", new ComposableIndexTemplate(List.of("logs-b-*"), null, List.of(), 2L, null, null))
                .build();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        assertTrue(upsert(metadata, "logs-*", "logs-b-000001", new ArrayList<>(), putIndexTemplateRequests).isAcknowledged());
        assertEquals(1, putIndexTemplateRequests.size());
        PutComposableIndexTemplateAction.Request request = putIndexTemplateRequests.get(0);
        assertEquals("logs", request.name());
        assertEquals(List.of(IndexTemplateUtils.computeComponentTemplateName("logs-*")), request.indexTemplate().composedOf());
    }

    public void testIndexPatternFailsOnConflictingTemplateWithoutPut() throws Exception {
        Metadata metadata = Metadata.builder()
                .put(index("rcxb-000001", "unrelated", null, 1L), false)
                .put("archive", new ComposableIndexTemplate(List.of("rcxb-archive-*"), null, List.of(), 0L, null, null))
                .build();
        List<PutComposableIndexTemplateAction.Request> putIndexTemplateRequests = new ArrayList<>();

        ExecutionException e = expectThrows(
                ExecutionException.class,
                () -> upsert(metadata, "rcxb*", "rcxb-000001", new ArrayList<>(), putIndexTemplateRequests)
        );
        assertTrue(e.getMessage(), e.getMessage().contains("Found conflicting template: [archive]"));
        assertTrue(putIndexTemplateRequests.isEmpty());
    }
}
