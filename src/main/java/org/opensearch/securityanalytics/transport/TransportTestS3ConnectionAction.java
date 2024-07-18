/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.action.TestS3ConnectionAction;
import org.opensearch.securityanalytics.action.TestS3ConnectionRequest;
import org.opensearch.securityanalytics.action.TestS3ConnectionResponse;
import org.opensearch.securityanalytics.services.STIX2IOCFetchService;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportTestS3ConnectionAction extends HandledTransportAction<TestS3ConnectionRequest, TestS3ConnectionResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportTestS3ConnectionAction.class);
    private final ThreadPool threadPool;

    private volatile Boolean filterByEnabled;

    private final Settings settings;

    private final STIX2IOCFetchService stix2IOCFetchService;

    @Inject
    public TransportTestS3ConnectionAction(
            TransportService transportService,
            ActionFilters actionFilters,
            final ThreadPool threadPool,
            Settings settings,
            STIX2IOCFetchService stix2IOCFetchService
            ) {
        super(TestS3ConnectionAction.NAME, transportService, actionFilters, TestS3ConnectionRequest::new);
        this.threadPool = threadPool;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.stix2IOCFetchService = stix2IOCFetchService;
    }

    @Override
    protected void doExecute(Task task, TestS3ConnectionRequest request, ActionListener<TestS3ConnectionResponse> listener) {
        // validate user
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }
        this.threadPool.getThreadContext().stashContext();
        try {
            stix2IOCFetchService.testS3Connection(request.constructS3ConnectorConfig(), listener);
        } catch (Exception e) {
            log.warn("S3 connection test failed with error: ", e);
            listener.onFailure(SecurityAnalyticsException.wrap(e));
        }
    }
}
