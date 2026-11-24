/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.alerts;

import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.CorrelationAlert;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertsList;
import org.opensearch.securityanalytics.resources.RecordingClient;
import org.opensearch.securityanalytics.resources.SecurityAnalyticsPluginClient;
import org.apache.lucene.search.TotalHits;
import org.opensearch.action.bulk.BulkAction;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.internal.InternalSearchResponse;
import org.opensearch.securityanalytics.action.AckCorrelationAlertsResponse;
import org.opensearch.securityanalytics.resources.TestPluginSubject;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class CorrelationAlertServiceTests  extends OpenSearchTestCase {

    public void testGetActiveAlerts() {
        // Mock setup; the plugin client class is final, so it wraps a mocked client instead of being mocked
        Client delegate = mock(Client.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));
        when(delegate.threadPool()).thenReturn(threadPool);
        SecurityAnalyticsPluginClient client = new SecurityAnalyticsPluginClient(delegate);
        client.setSubject(new TestPluginSubject(threadPool.getThreadContext()));
        NamedXContentRegistry xContentRegistry = mock(NamedXContentRegistry.class);
        CorrelationAlertService alertsService = spy(new CorrelationAlertService(client, xContentRegistry));


        // Fake data
        String ruleId = "correlation_rule_id_123";
        long currentTime = System.currentTimeMillis();

        // Define a fake correlation alert
        CorrelationAlert correlationAlert = new CorrelationAlert(
                Collections.emptyList(),
                ruleId,
                "mock-rule",
                UUID.randomUUID().toString(),
                1L,
                1,
                null,
                "mock-trigger",
                Alert.State.ACTIVE,
                Instant.ofEpochMilli(currentTime).minusMillis(1000L),
                Instant.ofEpochMilli(currentTime).plusMillis(1000L),
                null,
                null,
                "high",
                new ArrayList<>()
        );

        List<CorrelationAlert> correlationAlerts = Collections.singletonList(correlationAlert);

        // Call getActiveAlerts
        alertsService.getActiveAlerts(ruleId, currentTime, new ActionListener<CorrelationAlertsList>() {
            @Override
            public void onResponse(CorrelationAlertsList correlationAlertsList) {
                // Assertion
                assertEquals(correlationAlerts.size(), correlationAlertsList.getCorrelationAlertList().size());

                // Additional assertions can be added here to verify specific fields or states
                CorrelationAlert returnedAlert = correlationAlertsList.getCorrelationAlertList().get(0);
                assertEquals(correlationAlert.getId(), returnedAlert.getId());
                assertEquals(correlationAlert.getCorrelationRuleId(), returnedAlert.getCorrelationRuleId());
                assertEquals(correlationAlert.getStartTime(), returnedAlert.getStartTime());
                assertEquals(correlationAlert.getEndTime(), returnedAlert.getEndTime());
            }

            @Override
            public void onFailure(Exception e) {

            }
        });
    }

    public void testAcknowledgeAlertsSearchesAndUpdatesAsThePluginSubject() throws Exception {
        try (RecordingClient delegate = new RecordingClient(getTestName())) {
            SearchHit hit = new SearchHit(0, "alert-1", Collections.emptyMap(), Collections.emptyMap());
            CorrelationAlert alert = new CorrelationAlert(Collections.emptyList(), "rule-1", "rule", "alert-1", 1L, 1, null, "trigger",
                    Alert.State.ACTIVE, Instant.now(), Instant.now(), null, null, "high", new ArrayList<>());
            hit.sourceRef(BytesReference.bytes(alert.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)));
            SearchHits hits = new SearchHits(new SearchHit[] { hit }, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 1f);
            delegate.respond(SearchAction.INSTANCE, () -> new SearchResponse(
                    new InternalSearchResponse(hits, null, null, null, false, null, 1),
                    null, 1, 1, 0, 1, ShardSearchFailure.EMPTY_ARRAY, SearchResponse.Clusters.EMPTY));
            delegate.respond(BulkAction.INSTANCE, () -> new BulkResponse(new BulkItemResponse[0], 1));
            SecurityAnalyticsPluginClient client = new SecurityAnalyticsPluginClient(delegate);
            client.setSubject(new TestPluginSubject(delegate.threadPool().getThreadContext()));

            PlainActionFuture<AckCorrelationAlertsResponse> response = new PlainActionFuture<>();
            new CorrelationAlertService(client, NamedXContentRegistry.EMPTY).acknowledgeAlerts(List.of("alert-1"), response);
            response.get(10, TimeUnit.SECONDS);

            // The bulk is sent from the search callback, where the caller's context is back on the thread
            assertEquals(List.of(SearchAction.NAME, BulkAction.NAME),
                    delegate.calls().stream().map(RecordingClient.Call::action).collect(Collectors.toList()));
            for (RecordingClient.Call call : delegate.calls()) {
                assertEquals(call.action(), TestPluginSubject.NAME, call.subject());
            }
        }
    }
}
