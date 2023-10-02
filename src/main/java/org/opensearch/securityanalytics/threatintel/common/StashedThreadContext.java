/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.common;

import java.util.function.Supplier;

import org.opensearch.client.Client;
import org.opensearch.common.util.concurrent.ThreadContext;

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
}

