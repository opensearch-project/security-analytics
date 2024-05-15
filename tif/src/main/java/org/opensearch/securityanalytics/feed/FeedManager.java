/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.feed;

import com.google.common.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class FeedManager {
    private static final Logger log = LoggerFactory.getLogger(FeedManager.class);

    private final ScheduledExecutorService executorService;
    private final Map<String, ScheduledFuture<?>> registeredTasks;

    public FeedManager() {
        final ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1);
        scheduledThreadPoolExecutor.setRemoveOnCancelPolicy(true);

        executorService = Executors.unconfigurableScheduledExecutorService(scheduledThreadPoolExecutor);
        registeredTasks = new HashMap<>();
    }

    @VisibleForTesting
    FeedManager(final ScheduledExecutorService scheduledExecutorService, final Map<String, ScheduledFuture<?>> registeredTasks) {
        this.executorService = scheduledExecutorService;
        this.registeredTasks = registeredTasks;
    }

    public void registerFeedRetriever(final String feedId, final Runnable feedRetriever, final Duration refreshInterval) {
        if (registeredTasks.containsKey(feedId)) {
            log.warn("Field with ID {} already has a retriever registered. Will replace existing feed retriever with new definition.", feedId);
            deregisterFeedRetriever(feedId);
        }

        final ScheduledFuture<?> retrieverFuture = executorService.scheduleAtFixedRate(feedRetriever, 0, refreshInterval.toMillis(), TimeUnit.MILLISECONDS);
        registeredTasks.put(feedId, retrieverFuture);
    }

    public void deregisterFeedRetriever(final String feedId) {
        if (registeredTasks.containsKey(feedId)) {
            final ScheduledFuture<?> retrieverFuture = registeredTasks.remove(feedId);
            retrieverFuture.cancel(true);
        }
    }
}
