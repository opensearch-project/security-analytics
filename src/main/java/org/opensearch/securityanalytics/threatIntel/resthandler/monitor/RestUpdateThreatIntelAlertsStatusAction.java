package org.opensearch.securityanalytics.threatIntel.resthandler.monitor;

import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.AckAlertsAction;
import org.opensearch.securityanalytics.action.AckAlertsRequest;
import org.opensearch.securityanalytics.action.ListIOCsActionRequest;
import org.opensearch.securityanalytics.threatIntel.action.monitor.GetThreatIntelAlertsAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.UpdateThreatIntelAlertStatusAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.UpdateThreatIntelAlertStatusRequest;
import org.opensearch.securityanalytics.util.DetectorUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;

/**
 * Update status of list of threat intel alerts
 * Supported state to udpate to : ACKNOWLEDGED, COMPLETED
 */
public class RestUpdateThreatIntelAlertsStatusAction extends BaseRestHandler {
    @Override
    public String getName() {
        return "update_threat_intel_alerts_action";
    }

    @Override
    public List<Route> routes() {
        return Collections.singletonList(
                new Route(RestRequest.Method.PUT, String.format(
                        Locale.getDefault(),
                        "%s",
                        SecurityAnalyticsPlugin.THREAT_INTEL_ALERTS_STATUS_URI
                )
                ));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String state = request.param("state");
        Alert.State alertState = Alert.State.valueOf(state.toUpperCase());
        List<String> alertIds = List.of(
                Strings.commaDelimitedListToStringArray(
                        request.param(UpdateThreatIntelAlertStatusRequest.ALERT_IDS_FIELD, "")));
        UpdateThreatIntelAlertStatusRequest req = new UpdateThreatIntelAlertStatusRequest(alertIds, alertState);
        return channel -> client.execute(
                UpdateThreatIntelAlertStatusAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

}
