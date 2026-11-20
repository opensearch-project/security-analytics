/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.MatchAllQueryBuilder;
import org.opensearch.index.query.MoreLikeThisQueryBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.SearchCorrelationRuleRequest;
import org.opensearch.securityanalytics.action.SearchCustomLogTypeRequest;
import org.opensearch.securityanalytics.action.SearchRuleRequest;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.resources.RecordingClient;
import org.opensearch.securityanalytics.resources.SecurityAnalyticsPluginClient;
import org.opensearch.securityanalytics.resources.TestPluginSubject;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.SASearchTIFSourceConfigsRequest;
import org.opensearch.securityanalytics.threatIntel.service.DefaultTifSourceConfigLoaderService;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigManagementService;
import org.opensearch.securityanalytics.threatIntel.transport.TransportSearchTIFSourceConfigsAction;
import org.opensearch.securityanalytics.util.CorrelationRuleIndices;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.TestThreadPool;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Tests that each search taking the caller's source answers 400 when a part of it reads other documents. */
public class SearchActionsRefuseDocumentFetchTests extends OpenSearchTestCase {

    private ThreadPool threadPool;
    private ClusterService clusterService;
    private final ActionFilters actionFilters = new ActionFilters(Set.of());

    @Override
    public void setUp() throws Exception {
        super.setUp();
        threadPool = new TestThreadPool(getTestName());
        clusterService = mock(ClusterService.class);
        when(clusterService.getClusterSettings()).thenReturn(
                new ClusterSettings(Settings.EMPTY, Set.of(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES)));
    }

    @Override
    public void tearDown() throws Exception {
        terminate(threadPool);
        super.tearDown();
    }

    public void testLogTypeSearch() throws Exception {
        LogTypeService logTypeService = mock(LogTypeService.class);
        TransportSearchCustomLogTypeAction action = new TransportSearchCustomLogTypeAction(mock(TransportService.class), clusterService,
                actionFilters, threadPool, Settings.EMPTY, null, logTypeService);

        PlainActionFuture<SearchResponse> response = new PlainActionFuture<>();
        action.execute(mock(Task.class), new SearchCustomLogTypeRequest(new SearchRequest().source(fetchingSource())), response);

        assertBadRequest(response);
        verifyNoInteractions(logTypeService);
    }

    public void testRuleSearch() throws Exception {
        RuleIndices ruleIndices = mock(RuleIndices.class);
        when(ruleIndices.getThreadPool()).thenReturn(threadPool);
        TransportSearchRuleAction action = new TransportSearchRuleAction(mock(TransportService.class), null, actionFilters, clusterService,
                ruleIndices, Settings.EMPTY);

        PlainActionFuture<SearchResponse> response = new PlainActionFuture<>();
        action.execute(mock(Task.class), new SearchRuleRequest(true, new SearchRequest().source(fetchingSource())), response);

        assertBadRequest(response);
    }

    public void testThreatIntelSourceConfigSearch() throws Exception {
        DefaultTifSourceConfigLoaderService loader = mock(DefaultTifSourceConfigLoaderService.class);
        SATIFSourceConfigManagementService service = mock(SATIFSourceConfigManagementService.class);
        TransportSearchTIFSourceConfigsAction action = new TransportSearchTIFSourceConfigsAction(mock(TransportService.class), actionFilters,
                clusterService, threadPool, Settings.EMPTY, loader, service);

        PlainActionFuture<SearchResponse> response = new PlainActionFuture<>();
        action.execute(mock(Task.class), new SASearchTIFSourceConfigsRequest(fetchingSource()), response);

        assertBadRequest(response);
        verifyNoInteractions(loader, service);
    }

    public void testCorrelationRuleSearch() throws Exception {
        try (RecordingClient client = new RecordingClient(getTestName())) {
            SecurityAnalyticsPluginClient pluginClient = new SecurityAnalyticsPluginClient(client);
            pluginClient.setSubject(new TestPluginSubject(client.threadPool().getThreadContext()));
            TransportSearchCorrelationRuleAction action = new TransportSearchCorrelationRuleAction(mock(TransportService.class),
                    actionFilters, clusterService, mock(CorrelationRuleIndices.class), pluginClient);

            PlainActionFuture<SearchResponse> response = new PlainActionFuture<>();
            action.execute(mock(Task.class), new SearchCorrelationRuleRequest(new SearchRequest().source(fetchingSource())), response);

            assertBadRequest(response);
            assertTrue("nothing is searched", client.calls().isEmpty());
        }
    }

    /** A source whose query is harmless and whose post filter reads another document. */
    private static SearchSourceBuilder fetchingSource() {
        MoreLikeThisQueryBuilder.Item item = new MoreLikeThisQueryBuilder.Item("other", "1");
        return new SearchSourceBuilder().query(new MatchAllQueryBuilder())
                .postFilter(new MoreLikeThisQueryBuilder(new String[] { "field" }, null, new MoreLikeThisQueryBuilder.Item[] { item }));
    }

    private static void assertBadRequest(PlainActionFuture<SearchResponse> response) throws Exception {
        Throwable failure = expectThrows(ExecutionException.class, () -> response.get(10, TimeUnit.SECONDS)).getCause();
        if (!(failure instanceof OpenSearchStatusException statusException)) {
            throw new AssertionError("expected a status exception", failure);
        }
        assertEquals(RestStatus.BAD_REQUEST, statusException.status());
    }
}
