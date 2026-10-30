/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.action.admin.indices.create.CreateIndexAction;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexAction;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleRequest;
import org.opensearch.securityanalytics.action.IndexCorrelationRuleResponse;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.resources.RecordingClient;
import org.opensearch.securityanalytics.resources.SecurityAnalyticsPluginClient;
import org.opensearch.securityanalytics.resources.TestPluginSubject;
import org.opensearch.securityanalytics.util.CorrelationRuleIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;

import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Tests that a correlation rule is written as the plugin subject with the caller still the authenticated user. */
public class TransportIndexCorrelationRuleActionTests extends OpenSearchTestCase {

    public void testCreatesTheIndexAndWritesTheRuleAsThePluginSubjectForTheCaller() throws Exception {
        Boolean indexUpdated = IndexUtils.correlationRuleIndexUpdated;
        try (RecordingClient delegate = new RecordingClient(getTestName())) {
            delegate.respond(CreateIndexAction.INSTANCE, () -> new CreateIndexResponse(true, true, CorrelationRule.CORRELATION_RULE_INDEX));
            delegate.respond(IndexAction.INSTANCE, () -> new IndexResponse(new ShardId(CorrelationRule.CORRELATION_RULE_INDEX, "uuid", 0),
                    "rule-1", 1, 1, 1, true));
            ThreadContext threadContext = delegate.threadPool().getThreadContext();
            SecurityAnalyticsPluginClient pluginClient = new SecurityAnalyticsPluginClient(delegate);
            pluginClient.setSubject(new TestPluginSubject(threadContext));
            ClusterService clusterService = mock(ClusterService.class);
            when(clusterService.state()).thenReturn(ClusterState.EMPTY_STATE);
            TransportIndexCorrelationRuleAction action = new TransportIndexCorrelationRuleAction(mock(TransportService.class), pluginClient,
                    new ActionFilters(Set.of()), clusterService, new CorrelationRuleIndices(pluginClient, clusterService));

            PlainActionFuture<IndexCorrelationRuleResponse> response = new PlainActionFuture<>();
            try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
                threadContext.putPersistent(RecordingClient.AUTHENTICATED_USER_HEADER, "caller");
                CorrelationRule rule = new CorrelationRule(CorrelationRule.NO_ID, CorrelationRule.NO_VERSION, "rule", List.of(), 300000L, null);
                action.doExecute(null, new IndexCorrelationRuleRequest(null, rule, RestRequest.Method.POST), response);
            }
            response.get(10, TimeUnit.SECONDS);

            // The write is issued from the create index callback, on another thread
            assertEquals(List.of(CreateIndexAction.NAME, IndexAction.NAME),
                    delegate.calls().stream().map(RecordingClient.Call::action).collect(Collectors.toList()));
            for (RecordingClient.Call call : delegate.calls()) {
                assertEquals(call.action(), TestPluginSubject.NAME, call.subject());
                assertEquals(call.action(), "caller", call.authenticatedUser());
            }
        } finally {
            IndexUtils.correlationRuleIndexUpdated = indexUpdated;
        }
    }
}
