/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.common;

import java.util.concurrent.ExecutorService;

import org.opensearch.common.settings.Settings;
import org.opensearch.threadpool.ExecutorBuilder;
import org.opensearch.threadpool.FixedExecutorBuilder;
import org.opensearch.threadpool.ThreadPool;

/**
 * Provide a list of static methods related with executors for threat intel
 */
public class TIFExecutor {
    private static final String THREAD_POOL_NAME = "_plugin_sap_tifjob_update"; //TODO: name
    private final ThreadPool threadPool;

    public TIFExecutor(final ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    /**
     * We use fixed thread count of 1 for updating tif job as updating tif job is running background
     * once a day at most and no need to expedite the task.
     *
     * @param settings the settings
     * @return the executor builder
     */
    public static ExecutorBuilder executorBuilder(final Settings settings) {
        return new FixedExecutorBuilder(settings, THREAD_POOL_NAME, 1, 1000, THREAD_POOL_NAME, false);
    }

    /**
     * Return an executor service for tif job update task
     *
     * @return the executor service
     */
    public ExecutorService forJobSchedulerParameterUpdate() {
        return threadPool.executor(THREAD_POOL_NAME);
    }
}
