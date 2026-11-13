/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.BulkByScrollTask;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.index.reindex.ScrollableHitSource;
import org.opensearch.securityanalytics.action.DeleteCorrelationRuleRequest;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.resources.RecordingClient;
import org.opensearch.securityanalytics.resources.SecurityAnalyticsPluginClient;
import org.opensearch.securityanalytics.resources.TestPluginSubject;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;

/** Tests that a correlation rule is deleted as the plugin subject and that each outcome reaches the caller. */
public class TransportDeleteCorrelationRuleActionTests extends OpenSearchTestCase {

    private static final String RULE_ID = "rule-1";

    public void testDeletesTheRuleAndSearchesItsAlertsAsThePluginSubjectForTheCaller() throws Exception {
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        List<RecordingClient.Call> calls = delete(client -> client.respond(DeleteByQueryAction.INSTANCE, () -> byScrollResponse(false)),
                response);

        assertTrue(response.get(10, TimeUnit.SECONDS).isAcknowledged());
        // The alert search is sent from the delete callback, where the caller's context is back on the thread
        assertEquals(List.of(DeleteByQueryAction.NAME, SearchAction.NAME),
                calls.stream().map(RecordingClient.Call::action).collect(Collectors.toList()));
        for (RecordingClient.Call call : calls) {
            assertEquals(call.action(), TestPluginSubject.NAME, call.subject());
            assertEquals(call.action(), "caller", call.authenticatedUser());
        }
        DeleteByQueryRequest deleteRequest = (DeleteByQueryRequest) calls.get(0).request();
        assertArrayEquals(new String[] { CorrelationRule.CORRELATION_RULE_INDEX }, deleteRequest.indices());
        assertEquals(QueryBuilders.matchQuery("_id", RULE_ID), deleteRequest.getSearchRequest().source().query());
        assertTrue(deleteRequest.isRefresh());
        SearchRequest alertSearch = (SearchRequest) calls.get(1).request();
        assertArrayEquals(new String[] { CorrelationIndices.CORRELATION_ALERT_INDEX }, alertSearch.indices());
        assertEquals(QueryBuilders.boolQuery().must(QueryBuilders.termQuery("correlation_rule_id", RULE_ID)),
                alertSearch.source().query());
    }

    public void testATimedOutDeleteFailsWithRequestTimeoutAndLeavesTheAlerts() throws Exception {
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        List<RecordingClient.Call> calls = delete(client -> client.respond(DeleteByQueryAction.INSTANCE, () -> byScrollResponse(true)),
                response);

        OpenSearchStatusException timedOut = assertFailedWith(response, RestStatus.REQUEST_TIMEOUT);
        assertTrue(timedOut.getMessage(), timedOut.getMessage().contains(RULE_ID));
        assertOnlyTheDeleteRan(calls);
    }

    public void testAFailedDeleteReachesTheCallerWrappedWithItsStatusAndLeavesTheAlerts() throws Exception {
        OpenSearchStatusException denied = new OpenSearchStatusException("no permissions", RestStatus.FORBIDDEN);
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        List<RecordingClient.Call> calls = delete(client -> client.fail(DeleteByQueryAction.INSTANCE, denied), response);

        Throwable failure = expectThrows(ExecutionException.class, () -> response.get(10, TimeUnit.SECONDS)).getCause();
        if (!(failure instanceof SecurityAnalyticsException wrapped)) {
            throw new AssertionError("expected a wrapped exception", failure);
        }
        assertEquals(RestStatus.FORBIDDEN, wrapped.status());
        assertSame(denied, failure.getCause());
        assertOnlyTheDeleteRan(calls);
    }

    public void testABulkFailureOnTheDeleteFailsTheCallerAndLeavesTheAlerts() throws Exception {
        OpenSearchStatusException denied = new OpenSearchStatusException("no permissions for [indices:data/write/delete]",
                RestStatus.FORBIDDEN);
        BulkItemResponse.Failure bulkFailure = new BulkItemResponse.Failure(CorrelationRule.CORRELATION_RULE_INDEX, RULE_ID, denied);
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        List<RecordingClient.Call> calls = delete(
                client -> client.respond(DeleteByQueryAction.INSTANCE, () -> byScrollResponse(List.of(bulkFailure), List.of())),
                response);

        OpenSearchStatusException failed = assertFailedWith(response, RestStatus.FORBIDDEN);
        assertEquals("Correlation Rule with id " + RULE_ID + " cannot be deleted: " + bulkFailure.getMessage(), failed.getMessage());
        assertSame(denied, failed.getCause());
        assertOnlyTheDeleteRan(calls);
    }

    public void testASearchFailureOnTheDeleteFailsTheCallerAndLeavesTheAlerts() throws Exception {
        OpenSearchStatusException denied = new OpenSearchStatusException("no permissions for [indices:data/read/scroll]",
                RestStatus.FORBIDDEN);
        ScrollableHitSource.SearchFailure searchFailure = new ScrollableHitSource.SearchFailure(denied,
                CorrelationRule.CORRELATION_RULE_INDEX, 0, null);
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        List<RecordingClient.Call> calls = delete(
                client -> client.respond(DeleteByQueryAction.INSTANCE, () -> byScrollResponse(List.of(), List.of(searchFailure))),
                response);

        OpenSearchStatusException failed = assertFailedWith(response, RestStatus.FORBIDDEN);
        assertEquals("Correlation Rule with id " + RULE_ID + " cannot be deleted: " + denied, failed.getMessage());
        assertSame(denied, failed.getCause());
        assertOnlyTheDeleteRan(calls);
    }

    public void testTheHighestStatusTheResponseListsReachesTheCallerWithEveryReason() throws Exception {
        // The denial is listed first and the conflict is the higher status, so neither "first" nor "last" passes
        OpenSearchStatusException denied = new OpenSearchStatusException("no permissions for [indices:data/write/delete]",
                RestStatus.FORBIDDEN);
        BulkItemResponse.Failure deniedItem = new BulkItemResponse.Failure(CorrelationRule.CORRELATION_RULE_INDEX, RULE_ID, denied);
        BulkItemResponse.Failure conflictItem = new BulkItemResponse.Failure(CorrelationRule.CORRELATION_RULE_INDEX, RULE_ID,
                new OpenSearchStatusException("version conflict", RestStatus.CONFLICT));
        ScrollableHitSource.SearchFailure searchFailure = new ScrollableHitSource.SearchFailure(
                new OpenSearchStatusException("no permissions for [indices:data/read/scroll]", RestStatus.FORBIDDEN),
                CorrelationRule.CORRELATION_RULE_INDEX, 0, null);
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        List<RecordingClient.Call> calls = delete(
                client -> client.respond(DeleteByQueryAction.INSTANCE,
                        () -> byScrollResponse(List.of(deniedItem, conflictItem), List.of(searchFailure))),
                response);

        OpenSearchStatusException failed = assertFailedWith(response, RestStatus.CONFLICT);
        assertEquals("Correlation Rule with id " + RULE_ID + " cannot be deleted: " + deniedItem.getMessage() + "; "
                + conflictItem.getMessage() + "; " + searchFailure.getReason(), failed.getMessage());
        assertSame(denied, failed.getCause());
        assertOnlyTheDeleteRan(calls);
    }

    public void testATimedOutDeleteThatAlsoListsFailuresStillFailsWithRequestTimeout() throws Exception {
        BulkItemResponse.Failure bulkFailure = new BulkItemResponse.Failure(CorrelationRule.CORRELATION_RULE_INDEX, RULE_ID,
                new OpenSearchStatusException("version conflict", RestStatus.CONFLICT));
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        List<RecordingClient.Call> calls = delete(
                client -> client.respond(DeleteByQueryAction.INSTANCE, () -> byScrollResponse(true, 0, List.of(bulkFailure), List.of())),
                response);

        assertFailedWith(response, RestStatus.REQUEST_TIMEOUT);
        assertOnlyTheDeleteRan(calls);
    }

    /**
     * Asserts that the action failed the caller with a status exception of the given status, and returns it.
     *
     * @param response the future the action completes
     * @param status the status the caller must get
     * @return the failure, for the caller to assert its message on
     */
    private static OpenSearchStatusException assertFailedWith(PlainActionFuture<AcknowledgedResponse> response, RestStatus status) {
        Throwable failure = expectThrows(ExecutionException.class, () -> response.get(10, TimeUnit.SECONDS)).getCause();
        if (!(failure instanceof OpenSearchStatusException failed)) {
            throw new AssertionError("expected a status exception", failure);
        }
        assertEquals(status, failed.status());
        return failed;
    }

    /**
     * Asserts that the delete by query was the only action run, which is how these tests check that the alerts
     * were left alone: {@code updateCorrelationAlertsWithError} searches the alerts index on the same client as
     * its first act, so entering it always records a second call.
     *
     * @param calls the actions the client recorded
     */
    private static void assertOnlyTheDeleteRan(List<RecordingClient.Call> calls) {
        assertEquals(List.of(DeleteByQueryAction.NAME), calls.stream().map(RecordingClient.Call::action).collect(Collectors.toList()));
    }

    /**
     * Deletes {@link #RULE_ID} as the caller and returns the actions run once every callback has finished.
     * The caller asserts the outcome; this only waits for it, so that no answer is rejected by a closed client.
     *
     * @param answers sets how the recording client answers
     * @param response completed by the action
     * @return the recorded calls
     */
    private List<RecordingClient.Call> delete(Consumer<RecordingClient> answers, PlainActionFuture<AcknowledgedResponse> response)
            throws Exception {
        RecordingClient delegate = new RecordingClient(getTestName());
        try (delegate) {
            answers.accept(delegate);
            ThreadContext threadContext = delegate.threadPool().getThreadContext();
            SecurityAnalyticsPluginClient pluginClient = new SecurityAnalyticsPluginClient(delegate);
            pluginClient.setSubject(new TestPluginSubject(threadContext));
            TransportDeleteCorrelationRuleAction action = new TransportDeleteCorrelationRuleAction(mock(TransportService.class), pluginClient,
                    new ActionFilters(Set.of()), new CorrelationAlertService(pluginClient, NamedXContentRegistry.EMPTY));

            try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
                threadContext.putPersistent(RecordingClient.AUTHENTICATED_USER_HEADER, "caller");
                action.doExecute(null, new DeleteCorrelationRuleRequest(RULE_ID, WriteRequest.RefreshPolicy.IMMEDIATE), response);
            }
            try {
                response.get(10, TimeUnit.SECONDS);
            } catch (ExecutionException expected) {
                // The failure paths are asserted by the caller
            }
        }
        // Closing waits for the responder, so a call made after the listener completes is recorded too
        return delegate.calls();
    }

    private static BulkByScrollResponse byScrollResponse(boolean timedOut) {
        return byScrollResponse(timedOut, timedOut ? 0 : 1, Collections.emptyList(), Collections.emptyList());
    }

    /** A response for a delete that removed nothing because the given failures stopped it. */
    private static BulkByScrollResponse byScrollResponse(
            List<BulkItemResponse.Failure> bulkFailures,
            List<ScrollableHitSource.SearchFailure> searchFailures
    ) {
        return byScrollResponse(false, 0, bulkFailures, searchFailures);
    }

    private static BulkByScrollResponse byScrollResponse(
            boolean timedOut,
            long deleted,
            List<BulkItemResponse.Failure> bulkFailures,
            List<ScrollableHitSource.SearchFailure> searchFailures
    ) {
        BulkByScrollTask.Status status = new BulkByScrollTask.Status(null, 1, 0, 0, deleted, 1, 0, 0, 0, 0, TimeValue.ZERO, 0f, null,
                TimeValue.ZERO);
        return new BulkByScrollResponse(TimeValue.ZERO, status, bulkFailures, searchFailures, timedOut);
    }
}
