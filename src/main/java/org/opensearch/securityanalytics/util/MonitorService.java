/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.util.SetOnce;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.DeleteMonitorRequest;
import org.opensearch.commons.alerting.action.DeleteMonitorResponse;
import org.opensearch.rest.RestStatus;

/**
 * Alerting common class used for monitors manipulation
 */
public class MonitorService {
    private static final Logger log = LogManager.getLogger(MonitorService.class);

    private Client client;

    public MonitorService() {
    }

    public MonitorService(Client client) {
        this.client = client;
    }

    /**
     * Deletes the alerting monitors based on the given ids and notifies the listener that will be notified once all monitors have been deleted
     * @param monitorIds monitor ids to be deleted
     * @param refreshPolicy
     * @param listener listener that will be notified once all the monitors are being deleted
     */
    public void deleteAlertingMonitors(List<String> monitorIds, WriteRequest.RefreshPolicy refreshPolicy, ActionListener<List<DeleteMonitorResponse>> listener){
        if (monitorIds == null || monitorIds.isEmpty()) {
            listener.onResponse(new ArrayList<>());
            return;
        }
        ActionListener<DeleteMonitorResponse> deletesListener = new GroupedActionListener<>(new ActionListener<>() {
            @Override
            public void onResponse(Collection<DeleteMonitorResponse> responses) {
                SetOnce<RestStatus> errorStatusSupplier = new SetOnce<>();
                if (responses.stream().filter(response -> {
                    if (response.getStatus() != RestStatus.OK) {
                        log.error("Monitor [{}] could not be deleted. Status [{}]", response.getId(), response.getStatus());
                        errorStatusSupplier.trySet(response.getStatus());
                        return true;
                    }
                    return false;
                }).count() > 0) {
                    listener.onFailure(new OpenSearchStatusException("Monitor associated with detected could not be deleted", errorStatusSupplier.get()));
                }
                listener.onResponse(responses.stream().collect(Collectors.toList()));
            }
            @Override
            public void onFailure(Exception e) {
                log.error("Error deleting monitors", e.getSuppressed());
                listener.onFailure(e);
            }
        }, monitorIds.size());

        for (String monitorId : monitorIds) {
            deleteAlertingMonitor(monitorId, refreshPolicy, deletesListener);
        }
    }

    private void deleteAlertingMonitor(String monitorId, WriteRequest.RefreshPolicy refreshPolicy, ActionListener<DeleteMonitorResponse> listener) {
        DeleteMonitorRequest request = new DeleteMonitorRequest(monitorId, refreshPolicy);
        AlertingPluginInterface.INSTANCE.deleteMonitor((NodeClient) client, request, listener);
    }
}
