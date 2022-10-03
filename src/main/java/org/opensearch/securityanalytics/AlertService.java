package org.opensearch.securityanalytics;

import org.opensearch.action.ActionListener;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.GetAlertsRequest;
import org.opensearch.commons.alerting.action.GetAlertsResponse;

public class AlertService {
    private final Client client;

    public AlertService(Client client) {
        this.client = client;
    }

    public void getAlerts(GetAlertsRequest getAlertsRequest, ActionListener<GetAlertsResponse> actionListener) {
        AlertingPluginInterface.INSTANCE.getAlerts((NodeClient) client, getAlertsRequest, actionListener);
    }

}
