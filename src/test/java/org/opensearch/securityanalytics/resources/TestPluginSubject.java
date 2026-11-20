/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resources;

import org.opensearch.common.CheckedRunnable;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.identity.NamedPrincipal;
import org.opensearch.identity.PluginSubject;

import java.security.Principal;

/** Runs its body in a stashed context that carries a marker, as a real plugin subject runs it as the plugin. */
public final class TestPluginSubject implements PluginSubject {

    /** The transient this subject sets while its body runs. */
    public static final String SUBJECT_TRANSIENT = "test.plugin_subject";

    /** The value of {@link #SUBJECT_TRANSIENT} and the principal name. */
    public static final String NAME = "security-analytics";

    private final ThreadContext threadContext;

    /**
     * Builds a subject that runs on the given context.
     *
     * @param threadContext the context its body runs in
     */
    public TestPluginSubject(ThreadContext threadContext) {
        this.threadContext = threadContext;
    }

    @Override
    public Principal getPrincipal() {
        return new NamedPrincipal(NAME);
    }

    @Override
    public <E extends Exception> void runAs(CheckedRunnable<E> r) throws E {
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            threadContext.putTransient(SUBJECT_TRANSIENT, NAME);
            r.run();
        }
    }
}
