/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.BulkByScrollTask;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.ScrollableHitSource;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.resources.RecordingClient;
import org.opensearch.securityanalytics.resources.SecurityAnalyticsPluginClient;
import org.opensearch.securityanalytics.resources.TestPluginSubject;
import org.opensearch.test.OpenSearchTestCase;

import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static org.mockito.Mockito.mock;

/** Tests that deleting the pre-packaged rules reports every way the delete by query can fail. */
public class RuleIndicesDeleteRulesTests extends OpenSearchTestCase {

    public void testADeleteThatListsNoFailureSucceedsAsThePluginSubject() throws Exception {
        PlainActionFuture<BulkByScrollResponse> response = new PlainActionFuture<>();
        List<RecordingClient.Call> calls = deleteRules(client -> client.respond(DeleteByQueryAction.INSTANCE,
                () -> byScrollResponse(false, List.of(), List.of())), response);

        assertNotNull(response.get(10, TimeUnit.SECONDS));
        assertEquals(1, calls.size());
        assertEquals(TestPluginSubject.NAME, calls.get(0).subject());
    }

    public void testATimedOutDeleteFails() throws Exception {
        OpenSearchStatusException failure = deleteAndExpectFailure(byScrollResponse(true, List.of(), List.of()));
        assertEquals(RestStatus.REQUEST_TIMEOUT, failure.status());
    }

    public void testABulkFailureListedInTheResponseFails() throws Exception {
        OpenSearchStatusException denied = new OpenSearchStatusException("no permissions", RestStatus.FORBIDDEN);
        OpenSearchStatusException failure = deleteAndExpectFailure(byScrollResponse(false,
                List.of(new BulkItemResponse.Failure(Rule.PRE_PACKAGED_RULES_INDEX, "rule-1", denied)), List.of()));

        assertEquals(RestStatus.FORBIDDEN, failure.status());
        assertSame(denied, failure.getCause());
        assertTrue(failure.getMessage(), failure.getMessage().startsWith("Pre-packaged rules cannot be deleted: "));
    }

    public void testASearchFailureListedInTheResponseFails() throws Exception {
        Exception shardFailure = new IllegalStateException("shard failed");
        OpenSearchStatusException failure = deleteAndExpectFailure(byScrollResponse(false, List.of(),
                List.of(new ScrollableHitSource.SearchFailure(shardFailure, Rule.PRE_PACKAGED_RULES_INDEX, 0, null))));

        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, failure.status());
        assertSame(shardFailure, failure.getCause());
    }

    private OpenSearchStatusException deleteAndExpectFailure(BulkByScrollResponse deleteResponse) throws Exception {
        PlainActionFuture<BulkByScrollResponse> response = new PlainActionFuture<>();
        deleteRules(client -> client.respond(DeleteByQueryAction.INSTANCE, () -> deleteResponse), response);
        Throwable failure = expectThrows(ExecutionException.class, () -> response.get(10, TimeUnit.SECONDS)).getCause();
        if (!(failure instanceof OpenSearchStatusException statusException)) {
            throw new AssertionError("expected a status exception", failure);
        }
        return statusException;
    }

    private List<RecordingClient.Call> deleteRules(Consumer<RecordingClient> answers, PlainActionFuture<BulkByScrollResponse> response)
            throws Exception {
        RecordingClient delegate = new RecordingClient(getTestName());
        try (delegate) {
            answers.accept(delegate);
            SecurityAnalyticsPluginClient pluginClient = new SecurityAnalyticsPluginClient(delegate);
            pluginClient.setSubject(new TestPluginSubject(delegate.threadPool().getThreadContext()));
            new RuleIndices(mock(LogTypeService.class), pluginClient, null, delegate.threadPool()).deleteRules(response);
            try {
                response.get(10, TimeUnit.SECONDS);
            } catch (ExecutionException expected) {
                // The failure paths are asserted by the caller
            }
        }
        return delegate.calls();
    }

    private static BulkByScrollResponse byScrollResponse(
            boolean timedOut,
            List<BulkItemResponse.Failure> bulkFailures,
            List<ScrollableHitSource.SearchFailure> searchFailures
    ) {
        BulkByScrollTask.Status status = new BulkByScrollTask.Status(null, 1, 0, 0, 0, 1, 0, 0, 0, 0, TimeValue.ZERO, 0f, null,
                TimeValue.ZERO);
        return new BulkByScrollResponse(TimeValue.ZERO, status, bulkFailures, searchFailures, timedOut);
    }
}
