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
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.action.AckCorrelationAlertsAction;
import org.opensearch.securityanalytics.action.AckCorrelationAlertsRequest;
import org.opensearch.securityanalytics.action.AckCorrelationAlertsResponse;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

public class TransportAckCorrelationAlertsAction extends HandledTransportAction<AckCorrelationAlertsRequest, AckCorrelationAlertsResponse> implements SecureTransportAction {

    private final NamedXContentRegistry xContentRegistry;

    private final ClusterService clusterService;

    private final Settings settings;

    private final ThreadPool threadPool;

    private final CorrelationAlertService correlationAlertService;

    private volatile Boolean filterByEnabled;

    private static final Logger log = LogManager.getLogger(TransportGetCorrelationAlertsAction.class);


    @Inject
    public TransportAckCorrelationAlertsAction(TransportService transportService, CorrelationAlertService correlationAlertService, ActionFilters actionFilters, ClusterService clusterService, AckCorrelationAlertsAction correlationAckAlertsAction, ThreadPool threadPool, Settings settings, NamedXContentRegistry xContentRegistry, Client client) {
        super(correlationAckAlertsAction.NAME, transportService, actionFilters, AckCorrelationAlertsRequest::new);
        this.xContentRegistry = xContentRegistry;
        this.correlationAlertService = correlationAlertService;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(Task task, AckCorrelationAlertsRequest request, ActionListener<AckCorrelationAlertsResponse> actionListener) {

        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }

        this.threadPool.getThreadContext().stashContext();

        if (!request.getCorrelationAlertIds().isEmpty()) {
            correlationAlertService.acknowledgeAlerts(
                    request.getCorrelationAlertIds(),
                    actionListener
            );
        }
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}
