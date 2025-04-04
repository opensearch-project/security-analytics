/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.AckCorrelationAlertsAction;
import org.opensearch.securityanalytics.action.AckCorrelationAlertsRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;


/**
 * Acknowledge list of correlation alerts generated by correlation rules.
 */
public class RestAcknowledgeCorrelationAlertsAction  extends BaseRestHandler {
    @Override
    public String getName() {
        return "ack_correlation_alerts_action";
    }

    @Override
    public List<Route> routes() {
        return Collections.singletonList(
                new Route(RestRequest.Method.POST, String.format(
                        Locale.getDefault(),
                        "%s/_acknowledge/correlationAlerts",
                        SecurityAnalyticsPlugin.PLUGINS_BASE_URI)
                ));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient nodeClient) throws IOException {
        List<String> alertIds = getAlertIds(request.contentParser());
        AckCorrelationAlertsRequest CorrelationAckAlertsRequest = new AckCorrelationAlertsRequest(alertIds);
        return channel -> nodeClient.execute(
                AckCorrelationAlertsAction.INSTANCE,
                CorrelationAckAlertsRequest,
                new RestToXContentListener<>(channel)
        );
    }

    private List<String> getAlertIds(XContentParser xcp) throws IOException {
        List<String> ids = new ArrayList<>();
        ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            if (fieldName.equals("alertIds")) {
                ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                    ids.add(xcp.text());
                }
            }

        }
        return ids;
    }
}

