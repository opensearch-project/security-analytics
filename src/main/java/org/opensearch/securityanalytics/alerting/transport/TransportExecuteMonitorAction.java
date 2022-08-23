/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.TransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.alerting.action.ExecuteMonitorAction;
import org.opensearch.securityanalytics.alerting.action.ExecuteMonitorRequest;
import org.opensearch.securityanalytics.alerting.action.ExecuteMonitorResponse;
import org.opensearch.securityanalytics.alerting.model.Monitor;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.util.List;

public class TransportExecuteMonitorAction extends TransportAction<ExecuteMonitorRequest, ExecuteMonitorResponse> {

    private final Logger LOG = LogManager.getLogger(TransportExecuteMonitorAction.class);

    private final Client client;
    private final ClusterService cluster;

    @Inject
    public TransportExecuteMonitorAction(final TransportService transport,
                                         final Client client,
                                         final ActionFilters actionFilters,
                                         final NamedXContentRegistry xContentRegistry,
                                         final ClusterService clusterService,
                                         final Settings settings) {
        super(ExecuteMonitorAction.NAME, actionFilters, transport.getTaskManager());
        this.client = client;
        this.cluster = clusterService;

    }

    @Override
    protected void doExecute(final Task task, final ExecuteMonitorRequest request, final ActionListener<ExecuteMonitorResponse> actionListener) {
        try {
            actionListener.onResponse(new ExecuteMonitorResponse(new Monitor("dsaf", "Atype", 135L, "nae", 245L, "asdf", List.of())));
        } catch (final Exception e) {
            actionListener.onFailure(e);
        }
    }
}