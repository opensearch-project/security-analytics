/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.function.Predicate;

public enum ThrowableCheckingPredicates {
    MONITOR_NOT_FOUND(ThrowableCheckingPredicates::isMonitorNotFoundException),
    WORKFLOW_NOT_FOUND(ThrowableCheckingPredicates::isWorkflowNotFoundException),
    ALERTING_CONFIG_INDEX_NOT_FOUND(ThrowableCheckingPredicates::isAlertingConfigIndexNotFoundException);

    private final Predicate<Throwable> matcherPredicate;
    ThrowableCheckingPredicates(final Predicate<Throwable> matcherPredicate) {
        this.matcherPredicate = matcherPredicate;
    }

    public Predicate<Throwable> getMatcherPredicate() {
        return this.matcherPredicate;
    }

    private static boolean isMonitorNotFoundException(final Throwable e) {
        return e.getMessage().matches("(.*)Monitor(.*) is not found(.*)");
    }

    public static boolean isWorkflowNotFoundException(final Throwable e) {
        return e.getMessage().matches("(.*)Workflow(.*) not found(.*)");
    }

    public static boolean isAlertingConfigIndexNotFoundException(final Throwable e) {
        return e.getMessage().contains("Configured indices are not found: [.opendistro-alerting-config]");
    }
}
