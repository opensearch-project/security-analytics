/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resources;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionType;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.identity.Subject;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.FilterClient;

public class SecurityAnalyticsPluginClient extends FilterClient {

    private static final Logger log = LogManager.getLogger(SecurityAnalyticsPluginClient.class);

    private volatile Subject subject;

    public SecurityAnalyticsPluginClient(Client delegate) {
        super(delegate);
    }

    public void setSubject(Subject subject) {
        this.subject = subject;
    }

    @Override
    protected <Request extends ActionRequest, Response extends ActionResponse> void doExecute(
        ActionType<Response> action,
        Request request,
        ActionListener<Response> listener
    ) {
        Subject currentSubject = this.subject;
        if (currentSubject == null) {
            throw new IllegalStateException("SecurityAnalyticsPluginClient is not initialized with a subject.");
        }

        ThreadContext.StoredContext storedContext = threadPool().getThreadContext().newStoredContext(false);

        try {
            currentSubject.runAs(() -> {
                ActionListener<Response> wrappedListener = ActionListener.runBefore(listener, storedContext::restore);
                super.doExecute(action, request, wrappedListener);
            });
        } catch (Exception e) {
            storedContext.close();
            listener.onFailure(e);
        }
    }
}
