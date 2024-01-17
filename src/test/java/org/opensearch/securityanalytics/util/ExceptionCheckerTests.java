/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.junit.Assert;
import org.junit.Before;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class ExceptionCheckerTests extends OpenSearchTestCase {

    private ExceptionChecker exceptionChecker;

    @Before
    public void setup() {
        exceptionChecker = new ExceptionChecker();
    }

    public void testExceptionMatches() {
        final Exception e = new Exception("Monitor xyz is not found");

        final boolean result = exceptionChecker.doesGroupedActionListenerExceptionMatch(e, List.of(ThrowableCheckingPredicates.MONITOR_NOT_FOUND));
        Assert.assertTrue(result);
    }

    public void testExceptionDoesNotMatch() {
        final Exception e = new Exception(UUID.randomUUID().toString());

        final boolean result = exceptionChecker.doesGroupedActionListenerExceptionMatch(e, List.of(ThrowableCheckingPredicates.MONITOR_NOT_FOUND));
        Assert.assertFalse(result);
    }

    public void testExceptionMatches_WithSuppressed() {
        final Exception e = new Exception("Monitor xyz is not found");
        e.addSuppressed(new Exception("Monitor xyz is not found"));

        final boolean result = exceptionChecker.doesGroupedActionListenerExceptionMatch(e, List.of(ThrowableCheckingPredicates.MONITOR_NOT_FOUND));
        Assert.assertTrue(result);
    }

    public void testExceptionDoesNotMatch_WithSuppressed() {
        final Exception e = new Exception(UUID.randomUUID().toString());
        e.addSuppressed(new Exception(UUID.randomUUID().toString()));

        final boolean result = exceptionChecker.doesGroupedActionListenerExceptionMatch(e, List.of(ThrowableCheckingPredicates.MONITOR_NOT_FOUND));
        Assert.assertFalse(result);
    }

    public void testExceptionDoesNotMatch_SuppressedDoesntMatch() {
        final Exception e = new Exception("Monitor xyz is not found");
        e.addSuppressed(new Exception(UUID.randomUUID().toString()));

        final boolean result = exceptionChecker.doesGroupedActionListenerExceptionMatch(e, List.of(ThrowableCheckingPredicates.MONITOR_NOT_FOUND));
        Assert.assertFalse(result);
    }

    public void testExceptionDoesNotMatch_TopLevelDoesntMatch() {
        final Exception e = new Exception(UUID.randomUUID().toString());
        e.addSuppressed(new Exception("Monitor xyz is not found"));

        final boolean result = exceptionChecker.doesGroupedActionListenerExceptionMatch(e, List.of(ThrowableCheckingPredicates.MONITOR_NOT_FOUND));
        Assert.assertFalse(result);
    }

    public void testExceptionDoesNotMatch_EmptyPredicates() {
        final Exception e = new Exception("Monitor xyz is not found");

        final boolean result = exceptionChecker.doesGroupedActionListenerExceptionMatch(e, Collections.emptyList());
        Assert.assertFalse(result);
    }

    public void testExceptionDoesNotMatch_MultiplePredicates() {
        final Exception e = new Exception("Monitor xyz is not found");

        final boolean result = exceptionChecker.doesGroupedActionListenerExceptionMatch(e, List.of(
                ThrowableCheckingPredicates.WORKFLOW_NOT_FOUND,
                ThrowableCheckingPredicates.MONITOR_NOT_FOUND
        ));
        Assert.assertTrue(result);
    }
}
