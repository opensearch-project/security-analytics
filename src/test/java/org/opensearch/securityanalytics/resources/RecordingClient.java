/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resources;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.test.client.NoOpClient;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Records each action it is asked to run, with the subject and authenticated user on the thread, and answers the
 * actions given a response on another thread. Actions without a response never complete.
 */
public final class RecordingClient extends NoOpClient {

    /** The persistent header the security plugin keeps the authenticated user in. */
    public static final String AUTHENTICATED_USER_HEADER = "_opendistro_security_authenticated_user";

    /**
     * One recorded action.
     *
     * @param action the action name
     * @param request the request it was run with
     * @param subject the plugin subject marker on the thread, null when it ran as no subject
     * @param authenticatedUser the persistent authenticated user on the thread
     */
    public record Call(String action, ActionRequest request, String subject, Object authenticatedUser) {}

    private final List<Call> calls = new CopyOnWriteArrayList<>();
    private final Map<String, Supplier<? extends ActionResponse>> responses = new ConcurrentHashMap<>();
    private final ExecutorService responder = Executors.newSingleThreadExecutor();

    /**
     * Builds a client with its own thread pool.
     *
     * @param testName the name of the test, used for the thread pool
     */
    public RecordingClient(String testName) {
        super(testName);
    }

    /**
     * Makes the client answer an action with a response, on another thread.
     *
     * @param action the action to answer
     * @param response supplies the response
     * @return this client
     */
    public RecordingClient respond(ActionType<?> action, Supplier<? extends ActionResponse> response) {
        responses.put(action.name(), response);
        return this;
    }

    /**
     * Returns the actions run so far.
     *
     * @return the calls in the order they were made
     */
    public List<Call> calls() {
        return calls;
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <Request extends ActionRequest, Response extends ActionResponse> void doExecute(
            ActionType<Response> action,
            Request request,
            ActionListener<Response> listener
    ) {
        calls.add(new Call(action.name(), request, threadPool().getThreadContext().getTransient(TestPluginSubject.SUBJECT_TRANSIENT),
                threadPool().getThreadContext().getPersistent(AUTHENTICATED_USER_HEADER)));
        Supplier<? extends ActionResponse> response = responses.get(action.name());
        if (response != null) {
            responder.execute(() -> listener.onResponse((Response) response.get()));
        }
    }

    @Override
    public void close() {
        responder.shutdown();
        try {
            responder.awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        super.close();
    }
}
