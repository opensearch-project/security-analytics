/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.opensearch.client.node.NodeClient;
import org.opensearch.common.Table;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.cat.AbstractCatAction;
import org.opensearch.rest.action.cat.RestTable;

import java.util.List;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;

public class SecurityAnalyticsCat extends AbstractCatAction {

    private final SecurityAnalyticsPlugin plugin;

    public SecurityAnalyticsCat(final SecurityAnalyticsPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, "_plugins/_sap/monitors"), new Route(POST, "_plugins/_sap/monitors"));
    }

    @Override
    public String getName() {
        return "security_analytics";
    }

    @Override
    protected RestChannelConsumer doCatRequest(final RestRequest request, final NodeClient client) {
        final String message = request.param("message", "Security Analytics");
        final Table table = getTableWithHeader(request);
        table.startRow();
        table.addCell(message);
        table.endRow();

        if (request.method().equals(POST)) {
            this.plugin.createMonitor();
        } else if (request.method().equals(GET)) {
            this.plugin.executeMonitor();
        } else {
            return channel -> {
                channel.sendResponse(null);
            };
        }

        return channel -> {
            try {
                channel.sendResponse(RestTable.buildResponse(table, channel));
            } catch (final Exception e) {
                channel.sendResponse(new BytesRestResponse(channel, e));
            }
        };
    }

    @Override
    protected void documentation(StringBuilder sb) {
        sb.append(documentation());
    }

    public static String documentation() {
        return "_plugin/_sap/monitors\n";
    }

    @Override
    protected Table getTableWithHeader(RestRequest request) {
        final Table table = new Table();
        table.startHeaders();
        table.addCell("monitor", "desc:monitor");
        table.endHeaders();
        return table;
    }
}


