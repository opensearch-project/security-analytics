/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.common;

import java.util.function.Consumer;
import java.util.function.Supplier;

import org.opensearch.action.support.ContextPreservingActionListener;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.transport.client.Client;

/**
 * Helper class to run code with stashed thread context
 *
 * Code need to be run with stashed thread context if it interacts with system index
 * when security plugin is enabled.
 */
public class StashedThreadContext {
    /**
     * Set the thread context to default, this is needed to allow actions on model system index
     * when security plugin is enabled
     * @param function runnable that needs to be executed after thread context has been stashed, accepts and returns nothing
     */
    public static void run(final Client client, final Runnable function) {
        try (ThreadContext.StoredContext context = client.threadPool().getThreadContext().stashContext()) {
            function.run();
        }
    }

    /**
     * Set the thread context to default, this is needed to allow actions on model system index
     * when security plugin is enabled
     * @param function supplier function that needs to be executed after thread context has been stashed, return object
     */
    public static <T> T run(final Client client, final Supplier<T> function) {
        try (ThreadContext.StoredContext context = client.threadPool().getThreadContext().stashContext()) {
            return function.get();
        }
    }

    /**
     * Starts an asynchronous call in a stashed context and hands its listener back the caller's context, so only the
     * call itself runs with no user.
     *
     * @param client the client whose thread context is stashed
     * @param listener receives the result in the caller's context
     * @param call starts the call with the listener it must complete
     */
    public static <T> void runAndRestore(final Client client, final ActionListener<T> listener, final Consumer<ActionListener<T>> call) {
        ThreadContext threadContext = client.threadPool().getThreadContext();
        Supplier<ThreadContext.StoredContext> callerContext = threadContext.newRestorableContext(false);
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            call.accept(new ContextPreservingActionListener<>(callerContext, listener));
        }
    }
}
