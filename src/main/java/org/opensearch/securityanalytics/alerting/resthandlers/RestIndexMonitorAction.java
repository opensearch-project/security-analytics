/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.resthandlers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionType;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.action.IndexMonitorResponse;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.alerting.action.IndexMonitorRequest;
import org.opensearch.securityanalytics.alerting.model.Monitor;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.securityanalytics.Tokens.*;

public class RestIndexMonitorAction extends BaseRestHandler {

    private final Logger LOG = LogManager.getLogger(RestIndexMonitorAction.class);

    @Override
    public String getName() {
        return "idx_monitor_action";
    }


    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, SAP_BASE_URI + "/{" + MONITOR_ID + "}/"));
        //return List.of(new Route(POST, SAP_MONITORS_BASE_URI + "/monitors"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return channel -> {
            LOG.info("{} {}/{}", request.method(), SAP_MONITORS_BASE_URI, getName());
            //  final String monitorId = request.param(MONITOR_ID);
            //  final TimeValue requestEnd = request.paramAsTime(REQUEST_END, TimeValue.MAX_VALUE);
            // final boolean dryRun = request.paramAsBoolean(DRY_RUN, false);
            //if (null == monitorId || monitorId.isEmpty()) throw new IllegalArgumentException("missing monitorID");


            // ModelSerializer.read(response, Monitor.class);
            client.execute(new ActionType<>("cluster:admin/opendistro/alerting/monitor/write", IndexMonitorResponse::new),
                    new IndexMonitorRequest("1334", 1L, 5L, WriteRequest.RefreshPolicy.IMMEDIATE, RestRequest.Method.POST,
                            new Monitor(request.content().utf8ToString(), "dsf", 34354L, request.uri(), 3L, request.path(), List.of())),
                    new RestToXContentListener<>(channel));
        };
    }

    @Override
    public Set<String> responseParams() {
        return Set.of(MONITOR_ID);
    }
}
