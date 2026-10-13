/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

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
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.securityanalytics.action.GetAlertsPageAction;
import org.opensearch.securityanalytics.action.GetAlertsPageRequest;
import org.opensearch.securityanalytics.action.GetAlertsPageResponse;
import org.opensearch.securityanalytics.alerts.AlertsService;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

/**
 * Gets a page of alerts in cursor paging, see {@link GetAlertsPageRequest}. The detectors whose alerts are returned
 * are found as by {@link TransportGetAlertsAction}, with the same access checks:
 * <ul>
 *     <li>no detector id or detector type: the detectors visible to the caller, found through
 *     {@link TransportSearchDetectorAction}</li>
 *     <li>a detector id: the detector, got through {@link org.opensearch.securityanalytics.action.GetDetectorAction} as
 *     the caller, which fails if the caller cannot access it</li>
 *     <li>a detector type: the detectors of the log type visible to the caller, found through
 *     {@link TransportSearchDetectorAction}, not found if there are none</li>
 * </ul>
 * Their alerts are found with a single search of the alert indices of their log types (never through Alerting).
 */
public class TransportGetAlertsPageAction extends HandledTransportAction<GetAlertsPageRequest, GetAlertsPageResponse>
        implements SecureTransportAction {

    private final TransportSearchDetectorAction transportSearchDetectorAction;

    private final NamedXContentRegistry xContentRegistry;

    private final ThreadPool threadPool;

    private final AlertsService alertsService;

    private volatile Boolean filterByEnabled;

    @Inject
    public TransportGetAlertsPageAction(TransportService transportService, ActionFilters actionFilters, ClusterService clusterService,
                                        TransportSearchDetectorAction transportSearchDetectorAction, ThreadPool threadPool,
                                        Settings settings, NamedXContentRegistry xContentRegistry, Client client) {
        super(GetAlertsPageAction.NAME, transportService, actionFilters, GetAlertsPageRequest::new);
        this.transportSearchDetectorAction = transportSearchDetectorAction;
        this.xContentRegistry = xContentRegistry;
        this.alertsService = new AlertsService(client);
        this.threadPool = threadPool;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(settings);
        clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES,
                this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(Task task, GetAlertsPageRequest request, ActionListener<GetAlertsPageResponse> listener) {
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }

        boolean noDetectorId = request.getDetectorId() == null || request.getDetectorId().isEmpty();
        if (request.getLogType() == null && noDetectorId) {
            TransportGetAlertsAction.searchDetectors(transportSearchDetectorAction, xContentRegistry, QueryBuilders.matchAllQuery(),
                    ActionListener.wrap(detectors -> alertsService.getAlertsPage(detectors, request, listener), listener::onFailure));
        } else if (request.getLogType() == null) {
            alertsService.getAlertsPageByDetectorId(request.getDetectorId(), request, listener);
        } else {
            TransportGetAlertsAction.searchDetectors(transportSearchDetectorAction, xContentRegistry,
                    TransportGetAlertsAction.detectorTypeQuery(request.getLogType()), ActionListener.wrap(
                            detectors -> {
                                if (detectors.isEmpty()) {
                                    listener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException(
                                            "No detectors found for provided type", RestStatus.NOT_FOUND)));
                                    return;
                                }
                                alertsService.getAlertsPage(detectors, request, listener);
                            },
                            listener::onFailure
                    ));
        }
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}
