package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.action.*;
import org.opensearch.securityanalytics.correlation.alert.CorrelationAlertService;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportGetCorrelationAlertsAction extends HandledTransportAction<GetCorrelationAlertsRequest, GetCorrelationAlertsResponse> implements SecureTransportAction {

    private final NamedXContentRegistry xContentRegistry;

    private final ClusterService clusterService;

    private final Settings settings;

    private final ThreadPool threadPool;

    private final CorrelationAlertService correlationAlertService;

    private volatile Boolean filterByEnabled;

    private static final Logger log = LogManager.getLogger(TransportGetCorrelationAlertsAction.class);


    @Inject
    public TransportGetCorrelationAlertsAction(TransportService transportService, CorrelationAlertService correlationAlertService, ActionFilters actionFilters, ClusterService clusterService, GetCorrelationAlertsAction getCorrelationAlertsAction, ThreadPool threadPool, Settings settings, NamedXContentRegistry xContentRegistry, Client client) {
        super(getCorrelationAlertsAction.NAME, transportService, actionFilters, GetCorrelationAlertsRequest::new);
        this.xContentRegistry = xContentRegistry;
        this.correlationAlertService = correlationAlertService;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(Task task, GetCorrelationAlertsRequest request, ActionListener<GetCorrelationAlertsResponse> actionListener) {

        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }

        if (request.getCorrelationRuleId() != null) {
            correlationAlertService.getCorrelationAlerts(
                    request.getCorrelationRuleId(),
                    request.getTable(),
                    actionListener
            );
        } else {
            correlationAlertService.getCorrelationAlerts(
                    null,
                    request.getTable(),
                    actionListener
            );
        }
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}