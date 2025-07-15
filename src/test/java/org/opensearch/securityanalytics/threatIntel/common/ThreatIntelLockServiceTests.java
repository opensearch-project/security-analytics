/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.common;

import static org.mockito.Mockito.mock;
import static org.opensearch.securityanalytics.threatIntel.common.TIFLockService.LOCK_DURATION_IN_SECONDS;
import static org.opensearch.securityanalytics.threatIntel.common.TIFLockService.RENEW_AFTER_IN_SECONDS;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Assert;
import org.junit.Before;
import org.mockito.Mockito;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.jobscheduler.spi.utils.LockService;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.TestHelpers;

public class ThreatIntelLockServiceTests extends ThreatIntelTestCase {
    private TIFLockService threatIntelLockService;

    @Before
    public void init() {
        threatIntelLockService = new TIFLockService(clusterService, verifyingClient);
        threatIntelLockService.initialize(lockService);
    }

    public void testAcquireLock_whenCalled_thenNotBlocked() {
        long expectedDurationInMillis = 1000;

        Mockito.doAnswer(inv -> {
                    ActionListener<LockModel> listener = inv.getArgument(3);
                    listener.onResponse(null);          // or listener.onFailure(ex);
                    return null;                        // because the real method is void
                })
                .when(lockService)
                .acquireLockWithId(
                        Mockito.any(), // jobIndexName you expect
                        Mockito.any(), // lockDurationSeconds you expect
                        Mockito.any(), // lockId you expect
                        Mockito.any()  // listener – generics erase to ActionListener
                );
        Instant before = Instant.now();
        threatIntelLockService.acquireLock(null, null, ActionListener.wrap(
                r -> fail("Should not have been blocked"), e -> {
                    Instant after = Instant.now();
                    assertTrue(after.toEpochMilli() - before.toEpochMilli() < expectedDurationInMillis);
                }
        ));
    }

    public void testRenewLock_whenCalled_thenNotBlocked() {
        long expectedDurationInMillis = 1000;

        Mockito.doAnswer(inv -> {
                    ActionListener<LockModel> listener = inv.getArgument(1);
                    listener.onResponse(null);          // or listener.onFailure(ex);
                    return null;                        // because the real method is void
                })
                .when(lockService)
                .renewLock(
                        Mockito.any(), // lockModel
                        Mockito.any()  // listener – generics erase to ActionListener
                );
        Instant before = Instant.now();
        assertNull(threatIntelLockService.renewLock(null));
        Instant after = Instant.now();
        assertTrue(after.toEpochMilli() - before.toEpochMilli() < expectedDurationInMillis);
    }

    public void testGetRenewLockRunnable_whenLockIsFresh_thenDoNotRenew() {
        LockModel lockModel = new LockModel(
                TestHelpers.randomLowerCaseString(),
                TestHelpers.randomLowerCaseString(),
                Instant.now(),
                LOCK_DURATION_IN_SECONDS,
                false
        );

        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            // Verifying
            assertTrue(actionRequest instanceof UpdateRequest);
            return new UpdateResponse(
                    mock(ShardId.class),
                    TestHelpers.randomLowerCaseString(),
                    randomPositiveLong(),
                    randomPositiveLong(),
                    randomPositiveLong(),
                    DocWriteResponse.Result.UPDATED
            );
        });

        AtomicReference<LockModel> reference = new AtomicReference<>(lockModel);
        threatIntelLockService.getRenewLockRunnable(reference).run();
        assertEquals(lockModel, reference.get());
    }

    public void testGetRenewLockRunnable_whenLockIsStale_thenRenew() {
        LockModel lockModel = new LockModel(
                TestHelpers.randomLowerCaseString(),
                TestHelpers.randomLowerCaseString(),
                Instant.now().minusSeconds(RENEW_AFTER_IN_SECONDS),
                LOCK_DURATION_IN_SECONDS,
                false
        );

        verifyingClient.setExecuteVerifier((actionResponse, actionRequest) -> {
            // Verifying
            assertTrue(actionRequest instanceof UpdateRequest);
            return new UpdateResponse(
                    mock(ShardId.class),
                    TestHelpers.randomLowerCaseString(),
                    randomPositiveLong(),
                    randomPositiveLong(),
                    randomPositiveLong(),
                    DocWriteResponse.Result.UPDATED
            );
        });

        AtomicReference<LockModel> reference = new AtomicReference<>(lockModel);
        threatIntelLockService.getRenewLockRunnable(reference).run();
        assertNotEquals(lockModel, reference.get());
    }
}

