package org.opensearch.securityanalytics.util;

import org.junit.Assert;
import org.opensearch.test.OpenSearchTestCase;

import java.util.UUID;

public class ThrowableCheckingPredicatesTests extends OpenSearchTestCase {

    public void testWorkflowNotFound_Success() {
        final Exception e = new Exception("Workflow " + UUID.randomUUID() + " not found");
        Assert.assertTrue(ThrowableCheckingPredicates.WORKFLOW_NOT_FOUND.getMatcherPredicate().test(e));
    }

    public void testWorkflowNotFound_Failure() {
        final Exception e = new Exception(UUID.randomUUID().toString());
        Assert.assertFalse(ThrowableCheckingPredicates.WORKFLOW_NOT_FOUND.getMatcherPredicate().test(e));
    }

    public void testMonitorNotFound_Success() {
        final Exception e = new Exception("Monitor " + UUID.randomUUID() + " is not found");
        Assert.assertTrue(ThrowableCheckingPredicates.MONITOR_NOT_FOUND.getMatcherPredicate().test(e));
    }

    public void testMonitorNotFound_Failure() {
        final Exception e = new Exception(UUID.randomUUID().toString());
        Assert.assertFalse(ThrowableCheckingPredicates.MONITOR_NOT_FOUND.getMatcherPredicate().test(e));
    }

    public void testAlertingConfigIndexNotFound_Success() {
        final Exception e = new Exception(UUID.randomUUID() + "Configured indices are not found: [.opendistro-alerting-config]");
        Assert.assertTrue(ThrowableCheckingPredicates.ALERTING_CONFIG_INDEX_NOT_FOUND.getMatcherPredicate().test(e));
    }

    public void testAlertingConfigIndexNotFound_Failure() {
        final Exception e = new Exception(UUID.randomUUID().toString());
        Assert.assertFalse(ThrowableCheckingPredicates.ALERTING_CONFIG_INDEX_NOT_FOUND.getMatcherPredicate().test(e));
    }
}
