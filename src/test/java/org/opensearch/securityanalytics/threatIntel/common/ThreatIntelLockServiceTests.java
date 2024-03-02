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

import org.junit.Before;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.TestHelpers;

public class ThreatIntelLockServiceTests extends ThreatIntelTestCase {
    private TIFLockService threatIntelLockService;
    private TIFLockService noOpsLockService;

    @Before
    public void init() {
        threatIntelLockService = new TIFLockService(clusterService, verifyingClient);
        noOpsLockService = new TIFLockService(clusterService, client);
    }

    public void testAcquireLock_whenValidInput_thenSucceed() {
        // Cannot test because LockService is final class
        // Simply calling method to increase coverage
        noOpsLockService.acquireLock(TestHelpers.randomLowerCaseString(), randomPositiveLong(), mock(ActionListener.class));
    }

    public void testAcquireLock_whenCalled_thenNotBlocked() {
        long expectedDurationInMillis = 1000;
        Instant before = Instant.now();
        threatIntelLockService.acquireLock(null, null, ActionListener.wrap(
                r -> fail("Should not have been blocked"), e -> {
                    Instant after = Instant.now();
                    assertTrue(after.toEpochMilli() - before.toEpochMilli() < expectedDurationInMillis);
                }
        ));
    }

    public void testReleaseLock_whenValidInput_thenSucceed() {
        // Cannot test because LockService is final class
        // Simply calling method to increase coverage
        noOpsLockService.releaseLock(null);
    }

    public void testRenewLock_whenCalled_thenNotBlocked() {
        long expectedDurationInMillis = 1000;
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

