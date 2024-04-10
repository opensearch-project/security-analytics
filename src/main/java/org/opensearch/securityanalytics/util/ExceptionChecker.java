/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

public class ExceptionChecker {

    public boolean doesGroupedActionListenerExceptionMatch(final Exception ex, final List<ThrowableCheckingPredicates> exceptionMatchers) {
        // grouped action listener listens on multiple listeners but throws only one exception. If multiple
        // listeners fail the other exceptions are added as suppressed exceptions to the first failure.
        return Stream.concat(Arrays.stream(ex.getSuppressed()), Stream.of(ex))
                .allMatch(throwable -> doesExceptionMatch(throwable, exceptionMatchers));
    }

    private boolean doesExceptionMatch(final Throwable throwable, final List<ThrowableCheckingPredicates> exceptionMatchers) {
        return exceptionMatchers.stream()
                .map(ThrowableCheckingPredicates::getMatcherPredicate)
                .anyMatch(matcher -> matcher.test(throwable));
    }

}
