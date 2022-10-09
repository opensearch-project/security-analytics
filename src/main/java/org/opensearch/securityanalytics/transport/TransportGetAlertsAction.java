/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.action.GetAlertsAction;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.securityanalytics.action.GetAlertsResponse;
import org.opensearch.securityanalytics.action.GetFindingsAction;
import org.opensearch.securityanalytics.action.GetFindingsRequest;
import org.opensearch.securityanalytics.action.GetFindingsResponse;
import org.opensearch.securityanalytics.alerts.AlertsService;
import org.opensearch.securityanalytics.findings.FindingsService;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportGetAlertsAction extends HandledTransportAction<GetAlertsRequest, GetAlertsResponse> {

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final AlertsService alertsService;

    private static final Logger log = LogManager.getLogger(TransportGetAlertsAction.class);


    @Inject
    public TransportGetAlertsAction(TransportService transportService, ActionFilters actionFilters, NamedXContentRegistry xContentRegistry, Client client) {
        super(GetAlertsAction.NAME, transportService, actionFilters, GetAlertsRequest::new);
        this.xContentRegistry = xContentRegistry;
        this.client = client;
        this.alertsService = new AlertsService(client);
    }

    @Override
    protected void doExecute(Task task, GetAlertsRequest request, ActionListener<GetAlertsResponse> actionListener) {
        alertsService.getAlertsByDetectorId(
            request.getDetectorId(),
            request.getTable(),
            request.getSeverityLevel(),
            request.getAlertState(),
            actionListener
        );
    }

}