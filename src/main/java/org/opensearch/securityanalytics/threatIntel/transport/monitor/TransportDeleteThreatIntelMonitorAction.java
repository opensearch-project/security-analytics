package org.opensearch.securityanalytics.threatIntel.transport.monitor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.DeleteMonitorRequest;
import org.opensearch.commons.alerting.action.DeleteMonitorResponse;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.monitor.DeleteThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.DeleteThreatIntelMonitorRequest;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportDeleteThreatIntelMonitorAction extends HandledTransportAction<DeleteThreatIntelMonitorRequest, DeleteMonitorResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportDeleteThreatIntelMonitorAction.class);

    private final ThreadPool threadPool;
    private final Settings settings;
    private final NamedWriteableRegistry namedWriteableRegistry;
    private final Client client;
    private volatile Boolean filterByEnabled;

    @Inject
    public TransportDeleteThreatIntelMonitorAction(
            final TransportService transportService,
            final ActionFilters actionFilters,
            final ThreadPool threadPool,
            final Settings settings,
            final Client client,
            final NamedWriteableRegistry namedWriteableRegistry
    ) {
        super(DeleteThreatIntelMonitorAction.NAME, transportService, actionFilters, DeleteThreatIntelMonitorRequest::new);
        this.threadPool = threadPool;
        this.settings = settings;
        this.namedWriteableRegistry = namedWriteableRegistry;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, DeleteThreatIntelMonitorRequest request, ActionListener<DeleteMonitorResponse> listener) {
        User user = readUserFromThreadContext(this.threadPool);
        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException(validateBackendRoleMessage, RestStatus.FORBIDDEN)));
            return;
        }
        AlertingPluginInterface.INSTANCE.deleteMonitor((NodeClient) client,
                new DeleteMonitorRequest(request.getMonitorId(), WriteRequest.RefreshPolicy.IMMEDIATE),
                listener);
    }
}
