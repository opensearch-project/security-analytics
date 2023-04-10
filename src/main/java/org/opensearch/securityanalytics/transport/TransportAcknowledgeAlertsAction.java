/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.StepListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.alerting.action.GetAlertsResponse;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.AckAlertsRequest;
import org.opensearch.securityanalytics.action.AckAlertsResponse;
import org.opensearch.securityanalytics.action.AckAlertsAction;
import org.opensearch.securityanalytics.action.GetDetectorRequest;
import org.opensearch.securityanalytics.action.GetDetectorResponse;
import org.opensearch.securityanalytics.alerts.AlertsService;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportAcknowledgeAlertsAction extends HandledTransportAction<AckAlertsRequest, AckAlertsResponse> implements SecureTransportAction {
    private final TransportGetDetectorAction transportGetDetectorAction;

    private final NamedXContentRegistry xContentRegistry;

    private final ClusterService clusterService;

    private final Settings settings;

    private final ThreadPool threadPool;
    private final AlertsService alertsService;

    private volatile Boolean filterByEnabled;

    private static final Logger log = LogManager.getLogger(TransportAcknowledgeAlertsAction.class);

    @Inject
    public TransportAcknowledgeAlertsAction(TransportService transportService, ActionFilters actionFilters, ClusterService clusterService, ThreadPool threadPool, Settings settings, TransportGetDetectorAction transportGetDetectorAction, NamedXContentRegistry xContentRegistry, Client client) {
        super(AckAlertsAction.NAME, transportService, actionFilters, AckAlertsRequest::new);
        this.transportGetDetectorAction = transportGetDetectorAction;
        this.xContentRegistry = xContentRegistry;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.alertsService = new AlertsService(client);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(Task task, AckAlertsRequest request, ActionListener<AckAlertsResponse> actionListener) {

        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }

        GetDetectorRequest getDetectorRequest = new GetDetectorRequest(request.getDetectorId(), -3L);
        transportGetDetectorAction.doExecute(task, getDetectorRequest, new ActionListener<GetDetectorResponse>() {
            @Override
            public void onResponse(GetDetectorResponse getDetectorResponse) {
                StepListener<GetAlertsResponse> getAlertsResponseStepListener = new StepListener<>();
                alertsService.getAlerts(
                        request.getAlertIds(),
                        getDetectorResponse.getDetector(),
                        new Table("asc", "id", null, 10000, 0, null),
                        getAlertsResponseStepListener
                );
                getAlertsResponseStepListener.whenComplete(getAlertsResponse -> {
                    if (getAlertsResponse.getAlerts().size() == 0 || isDetectorAlertsMonitorMismatch(getDetectorResponse.getDetector(), getAlertsResponse)) {
                        actionListener.onFailure(new OpenSearchException("Detector alert mapping is not valid"));
                    } else {
                        alertsService.ackknowledgeAlerts(getAlertsResponse, getDetectorResponse, actionListener);
                    }
                }, actionListener::onFailure);
            }

            @Override
            public void onFailure(Exception e) {
                actionListener.onFailure(e);
            }
        });
    }

    private boolean isDetectorAlertsMonitorMismatch(Detector detector, GetAlertsResponse getAlertsResponse) {
        return getAlertsResponse.getAlerts().stream()
                .anyMatch(alert -> false == detector.getMonitorIds().contains(alert.getMonitorId())) ;
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}
