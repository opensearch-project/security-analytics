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
import org.opensearch.commons.model2.action.IndexMonitorAction;
import org.opensearch.commons.model2.action.IndexMonitorRequest;
import org.opensearch.commons.model2.action.IndexMonitorResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;


public class TransportIndexMonitorAction extends TransportAction<IndexMonitorRequest, IndexMonitorResponse> {

    private final Logger LOG = LogManager.getLogger(TransportIndexMonitorAction.class);

    private final Client client;
    private final ClusterService cluster;

    @Inject
    public TransportIndexMonitorAction(final TransportService transport,
                                       final Client client,
                                       final ActionFilters actionFilters,
                                       final NamedXContentRegistry xContentRegistry,
                                       final ClusterService clusterService,
                                       final Settings settings) {
        super("cluster:admin/opendistro/sap/monitor/write2", actionFilters, transport.getTaskManager());
        this.client = client;
        this.cluster = clusterService;
    }

    @Override
    protected void doExecute(final Task task, IndexMonitorRequest request, final ActionListener<IndexMonitorResponse> actionListener) {
        try {
            this.client.execute(IndexMonitorAction.SAP_ALERTING_BRIDGE_INSTANCE, request, actionListener);
        } catch (final Exception e) {
            actionListener.onFailure(e);
        }
    }
}