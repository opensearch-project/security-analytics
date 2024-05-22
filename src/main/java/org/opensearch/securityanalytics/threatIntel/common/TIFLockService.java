/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.common;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.jobscheduler.spi.utils.LockService;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;

import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.JOB_INDEX_NAME;

/**
 * A wrapper of job scheduler's lock service
 */
public class TIFLockService {
    private static final Logger log = LogManager.getLogger(TIFLockService.class);

    public static final long LOCK_DURATION_IN_SECONDS = 300l;
    public static final long RENEW_AFTER_IN_SECONDS = 120l;
    private final ClusterService clusterService;
    private final LockService lockService;


    /**
     * Constructor
     *
     * @param clusterService the cluster service
     * @param client the client
     */
    public TIFLockService(final ClusterService clusterService, final Client client) {
        this.clusterService = clusterService;
        this.lockService = new LockService(client, clusterService);
    }

    /**
     * Synchronous method of #acquireLock
     *
     * @param tifJobName tifJobName to acquire lock on
     * @param lockDurationSeconds the lock duration in seconds
     */
    public void acquireLock(final String tifJobName, final Long lockDurationSeconds, ActionListener<LockModel> listener) {
        AtomicReference<LockModel> lockReference = new AtomicReference();
        lockService.acquireLockWithId(JOB_INDEX_NAME, lockDurationSeconds, tifJobName, new ActionListener<>() {
            @Override
            public void onResponse(final LockModel lockModel) {
                lockReference.set(lockModel);
                listener.onResponse(lockReference.get());
            }

            @Override
            public void onFailure(final Exception e) {
                log.error("Failed to acquire lock for tif job " + tifJobName, e);
                listener.onFailure(e);
            }
        });
    }

    /**
     * Wrapper method of LockService#release
     *
     * @param lockModel the lock model
     */
    public void releaseLock(final LockModel lockModel) {
        lockService.release(
                lockModel,
                ActionListener.wrap(released -> {}, exception -> log.error("Failed to release the lock", exception))
        );
    }

    /**
     * Synchronous method of LockService#renewLock
     *
     * @param lockModel lock to renew
     * @return renewed lock if renew succeed and null otherwise
     */
    public LockModel renewLock(final LockModel lockModel) {
        AtomicReference<LockModel> lockReference = new AtomicReference();
        CountDownLatch countDownLatch = new CountDownLatch(1);
        lockService.renewLock(lockModel, new ActionListener<>() {
            @Override
            public void onResponse(final LockModel lockModel) {
                lockReference.set(lockModel);
                countDownLatch.countDown();
            }

            @Override
            public void onFailure(final Exception e) {
                log.error("failed to renew lock", e);
                lockReference.set(null);
                countDownLatch.countDown();
            }
        });

        try {
            countDownLatch.await(clusterService.getClusterSettings().get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT).getSeconds(), TimeUnit.SECONDS);
            return lockReference.get();
        } catch (InterruptedException e) {
            log.error("Interrupted exception", e);
            return null;
        }
    }

    /**
     * Return a runnable which can renew the given lock model
     *
     * The runnable renews the lock and store the renewed lock in the AtomicReference.
     * It only renews the lock when it passed {@code RENEW_AFTER_IN_SECONDS} since
     * the last time the lock was renewed to avoid resource abuse.
     *
     * @param lockModel lock model to renew
     * @return runnable which can renew the given lock for every call
     */
    public Runnable getRenewLockRunnable(final AtomicReference<LockModel> lockModel) {
        return () -> {
            LockModel preLock = lockModel.get();
            if (Instant.now().isBefore(preLock.getLockTime().plusSeconds(RENEW_AFTER_IN_SECONDS))) {
                return;
            }
            lockModel.set(renewLock(lockModel.get()));
            if (lockModel.get() == null) {
                log.error("Exception: failed to renew a lock");
                new OpenSearchException("failed to renew a lock [{}]", preLock);
            }
        };
    }
}