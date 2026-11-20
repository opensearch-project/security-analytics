/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.test.client.NoOpClient;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.action.ActionType;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.BulkByScrollTask;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.index.reindex.ScrollableHitSource;
import org.opensearch.index.reindex.UpdateByQueryAction;
import org.opensearch.index.reindex.UpdateByQueryRequest;
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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;

/** Tests that a correlation rule is deleted as the plugin subject and that each outcome reaches the caller. */
public class TransportDeleteCorrelationRuleActionTests extends OpenSearchTestCase {

    private static final String RULE_ID = "rule-1";

    public void testDeletesTheRuleAndMarksItsAlertsAsThePluginSubjectForTheCaller() throws Exception {
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        List<RecordingClient.Call> calls = delete(client -> client
                .respond(DeleteByQueryAction.INSTANCE, () -> byScrollResponse(false))
                .respond(UpdateByQueryAction.INSTANCE, () -> byScrollResponse(false)), response);

        assertTrue(response.get(10, TimeUnit.SECONDS).isAcknowledged());
        // The alert update is sent from the delete callback, where the caller's context is back on the thread
        assertEquals(List.of(DeleteByQueryAction.NAME, UpdateByQueryAction.NAME),
                calls.stream().map(RecordingClient.Call::action).collect(Collectors.toList()));
        for (RecordingClient.Call call : calls) {
            assertEquals(call.action(), TestPluginSubject.NAME, call.subject());
            assertEquals(call.action(), "caller", call.authenticatedUser());
        }
        DeleteByQueryRequest deleteRequest = (DeleteByQueryRequest) calls.get(0).request();
        assertArrayEquals(new String[] { CorrelationRule.CORRELATION_RULE_INDEX }, deleteRequest.indices());
        assertEquals(QueryBuilders.matchQuery("_id", RULE_ID), deleteRequest.getSearchRequest().source().query());
        assertTrue(deleteRequest.isRefresh());
        UpdateByQueryRequest alertUpdate = (UpdateByQueryRequest) calls.get(1).request();
        assertArrayEquals(new String[] { CorrelationIndices.CORRELATION_ALERT_INDEX }, alertUpdate.indices());
        assertEquals(QueryBuilders.termQuery("correlation_rule_id", RULE_ID), alertUpdate.getSearchRequest().source().query());
        assertEquals("ERROR", alertUpdate.getScript().getParams().get("state"));
        assertTrue(alertUpdate.isRefresh());
        assertFalse("an alert acknowledged at the same moment does not fail the delete", alertUpdate.isAbortOnVersionConflict());
    }

    public void testAnAlertUpdatedConcurrentlyDoesNotFailTheDelete() throws Exception {
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        BulkByScrollTask.Status withConflict = new BulkByScrollTask.Status(null, 2, 1, 0, 0, 1, 1, 0, 0, 0, TimeValue.ZERO, 0f, null,
                TimeValue.ZERO);
        delete(client -> client
                .respond(DeleteByQueryAction.INSTANCE, () -> byScrollResponse(false))
                .respond(UpdateByQueryAction.INSTANCE, () -> new BulkByScrollResponse(TimeValue.ZERO, withConflict,
                        Collections.emptyList(), Collections.emptyList(), false)), response);

        assertTrue(response.get(10, TimeUnit.SECONDS).isAcknowledged());
    }

    public void testAListenerThatThrowsIsNotCompletedAgainAsAFailure() throws Exception {
        AtomicInteger failures = new AtomicInteger();
        // Answers on the calling thread, so the exception the listener throws comes back to this test.
        try (NoOpClient delegate = new NoOpClient(getTestName()) {
            @Override
            @SuppressWarnings("unchecked")
            protected <Request extends ActionRequest, Response extends ActionResponse> void doExecute(
                    ActionType<Response> action, Request request, ActionListener<Response> listener) {
                listener.onResponse((Response) byScrollResponse(false));
            }
        }) {
            SecurityAnalyticsPluginClient pluginClient = new SecurityAnalyticsPluginClient(delegate);
            pluginClient.setSubject(new TestPluginSubject(delegate.threadPool().getThreadContext()));
            CorrelationAlertService service = new CorrelationAlertService(pluginClient, NamedXContentRegistry.EMPTY);

            expectThrows(IllegalStateException.class, () -> service.updateCorrelationAlertsWithError(RULE_ID, new ActionListener<>() {
                @Override
                public void onResponse(Void unused) {
                    throw new IllegalStateException("thrown by the caller's listener");
                }

                @Override
                public void onFailure(Exception e) {
                    failures.incrementAndGet();
                }
            }));
        }
        assertEquals("the listener was completed only once", 0, failures.get());
    }

    public void testAFailedAlertUpdateReachesTheCaller() throws Exception {
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        OpenSearchStatusException denied = denial("indices:data/write/update/byquery");
        delete(client -> client
                .respond(DeleteByQueryAction.INSTANCE, () -> byScrollResponse(false))
                .fail(UpdateByQueryAction.INSTANCE, denied), response);

        ExecutionException e = expectThrows(ExecutionException.class, () -> response.get(10, TimeUnit.SECONDS));
        assertEquals(RestStatus.FORBIDDEN, ((SecurityAnalyticsException) e.getCause()).status());
    }

    public void testAnAlertUpdateThatListsAFailureReachesTheCaller() throws Exception {
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        BulkByScrollResponse listed = byScrollResponse(false, 0, List.of(new BulkItemResponse.Failure(
                CorrelationIndices.CORRELATION_ALERT_INDEX, "alert-1", denial("indices:data/write/update"))), Collections.emptyList());
        delete(client -> client
                .respond(DeleteByQueryAction.INSTANCE, () -> byScrollResponse(false))
                .respond(UpdateByQueryAction.INSTANCE, () -> listed), response);

        ExecutionException e = expectThrows(ExecutionException.class, () -> response.get(10, TimeUnit.SECONDS));
        SecurityAnalyticsException failure = (SecurityAnalyticsException) e.getCause();
        assertEquals(RestStatus.FORBIDDEN, failure.status());
        assertTrue(failure.getMessage(), failure.getMessage().contains("were not all marked as errored"));
    }

    public void testATimedOutAlertUpdateReachesTheCaller() throws Exception {
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        delete(client -> client
                .respond(DeleteByQueryAction.INSTANCE, () -> byScrollResponse(false))
                .respond(UpdateByQueryAction.INSTANCE, () -> byScrollResponse(true)), response);

        ExecutionException e = expectThrows(ExecutionException.class, () -> response.get(10, TimeUnit.SECONDS));
        assertEquals(RestStatus.REQUEST_TIMEOUT, ((SecurityAnalyticsException) e.getCause()).status());
    }

    public void testNoAlertIndexMeansNoAlertToMark() throws Exception {
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        delete(client -> client
                .respond(DeleteByQueryAction.INSTANCE, () -> byScrollResponse(false))
                .fail(UpdateByQueryAction.INSTANCE, new IndexNotFoundException(CorrelationIndices.CORRELATION_ALERT_INDEX)), response);

        assertTrue(response.get(10, TimeUnit.SECONDS).isAcknowledged());
    }

    public void testATimedOutDeleteFailsWithRequestTimeoutAndLeavesTheAlerts() throws Exception {
        OpenSearchStatusException timedOut = deleteAndExpect(byScrollResponse(true), RestStatus.REQUEST_TIMEOUT);

        assertTrue(timedOut.getMessage(), timedOut.getMessage().contains(RULE_ID));
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
        OpenSearchStatusException denied = denial("indices:data/write/delete");
        BulkItemResponse.Failure bulkFailure = bulkFailure(denied);

        OpenSearchStatusException failed = deleteAndExpect(byScrollResponse(false, 0, List.of(bulkFailure), List.of()),
                RestStatus.FORBIDDEN);

        assertEquals("Correlation Rule with id " + RULE_ID + " cannot be deleted: " + bulkFailure.getMessage(), failed.getMessage());
        assertSame(denied, failed.getCause());
    }

    public void testASearchFailureOnTheDeleteFailsTheCallerAndLeavesTheAlerts() throws Exception {
        OpenSearchStatusException denied = denial("indices:data/read/scroll");

        OpenSearchStatusException failed = deleteAndExpect(byScrollResponse(false, 0, List.of(), List.of(searchFailure(denied))),
                RestStatus.FORBIDDEN);

        assertEquals("Correlation Rule with id " + RULE_ID + " cannot be deleted: " + denied, failed.getMessage());
        assertSame(denied, failed.getCause());
    }

    public void testTheHighestStatusTheResponseListsReachesTheCallerWithEveryReason() throws Exception {
        // The denial is listed first and the conflict is the higher status, so neither "first" nor "last" passes
        OpenSearchStatusException denied = denial("indices:data/write/delete");
        BulkItemResponse.Failure deniedItem = bulkFailure(denied);
        BulkItemResponse.Failure conflictItem = bulkFailure(new OpenSearchStatusException("version conflict", RestStatus.CONFLICT));
        ScrollableHitSource.SearchFailure searchFailure = searchFailure(denial("indices:data/read/scroll"));

        OpenSearchStatusException failed = deleteAndExpect(
                byScrollResponse(false, 0, List.of(deniedItem, conflictItem), List.of(searchFailure)), RestStatus.CONFLICT);

        assertEquals("Correlation Rule with id " + RULE_ID + " cannot be deleted: " + deniedItem.getMessage() + "; "
                + conflictItem.getMessage() + "; " + searchFailure.getReason(), failed.getMessage());
        assertSame(denied, failed.getCause());
    }

    public void testATimedOutDeleteThatAlsoListsFailuresStillFailsWithRequestTimeout() throws Exception {
        BulkItemResponse.Failure bulkFailure = bulkFailure(new OpenSearchStatusException("version conflict", RestStatus.CONFLICT));

        deleteAndExpect(byScrollResponse(true, 0, List.of(bulkFailure), List.of()), RestStatus.REQUEST_TIMEOUT);
    }

    /**
     * Deletes {@link #RULE_ID} against a response the client answers with, asserts the caller got the given
     * status and that the alerts were left alone, and returns the failure.
     *
     * @param deleteResponse what the client answers the delete by query with
     * @param status the status the caller must get
     * @return the failure, for the caller to assert its message and cause on
     */
    private OpenSearchStatusException deleteAndExpect(BulkByScrollResponse deleteResponse, RestStatus status) throws Exception {
        PlainActionFuture<AcknowledgedResponse> response = new PlainActionFuture<>();
        List<RecordingClient.Call> calls = delete(client -> client.respond(DeleteByQueryAction.INSTANCE, () -> deleteResponse), response);

        Throwable failure = expectThrows(ExecutionException.class, () -> response.get(10, TimeUnit.SECONDS)).getCause();
        if (!(failure instanceof OpenSearchStatusException failed)) {
            throw new AssertionError("expected a status exception", failure);
        }
        assertEquals(status, failed.status());
        assertOnlyTheDeleteRan(calls);
        return failed;
    }

    /**
     * Asserts that the delete by query was the only action run, which is how these tests check that the alerts
     * were left alone: {@code updateCorrelationAlertsWithError} sends its update by query on the same client as
     * its first act, so entering it always records a second call.
     *
     * @param calls the actions the client recorded
     */
    private static void assertOnlyTheDeleteRan(List<RecordingClient.Call> calls) {
        assertEquals(List.of(DeleteByQueryAction.NAME), calls.stream().map(RecordingClient.Call::action).collect(Collectors.toList()));
    }

    private static OpenSearchStatusException denial(String action) {
        return new OpenSearchStatusException("no permissions for [" + action + "]", RestStatus.FORBIDDEN);
    }

    private static BulkItemResponse.Failure bulkFailure(Exception cause) {
        return new BulkItemResponse.Failure(CorrelationRule.CORRELATION_RULE_INDEX, RULE_ID, cause);
    }

    private static ScrollableHitSource.SearchFailure searchFailure(Exception cause) {
        return new ScrollableHitSource.SearchFailure(cause, CorrelationRule.CORRELATION_RULE_INDEX, 0, null);
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
