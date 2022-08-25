/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.resthandlers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.model2.action.IndexMonitorAction;
import org.opensearch.commons.model2.action.IndexMonitorRequest;
import org.opensearch.commons.model2.model.Monitor;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestStatusToXContentListener;

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
        // TODO: for some reason, the commment out line leads to "no handler found."
        // TODO: even though goth ultimately resolve to the same URI when monitorId=monitors
        return List.of(new Route(POST, SAP_BASE_URI + "/{" + MONITOR_ID + "}/"));
        //return List.of(new Route(POST, SAP_MONITORS_BASE_URI + "/monitors"));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return channel -> {
            LOG.info("{} {}/{}", request.method(), SAP_MONITORS_BASE_URI, getName());
            final String monitorId = request.param(MONITOR_ID);
            if (null == monitorId || monitorId.isEmpty()) throw new IllegalArgumentException("missing monitorID");
            /*long seqNo = request.paramAsLong(IF_SEQ_NO, SequenceNumbers.UNASSIGNED_SEQ_NO);
            long primaryTerm = request.paramAsLong(IF_PRIMARY_TERM, SequenceNumbers.UNASSIGNED_PRIMARY_TERM);
            WriteRequest.RefreshPolicy refreshPolicy = (request.hasParam(REFRESH)) ? WriteRequest.RefreshPolicy.parse(request.param(REFRESH)) : WriteRequest.RefreshPolicy.IMMEDIATE;
            XContentParser parser = request.contentParser();
            final Monitor monitor = ModelSerializer.read(parser, Monitor.class);*/

            client.execute(
                    IndexMonitorAction.SAP_ALERTING_BRIDGE_INSTANCE,
                    new IndexMonitorRequest(monitorId, 3L, 4L, WriteRequest.RefreshPolicy.IMMEDIATE, request.method(), new Monitor("anid", "atype", 12L, null, "hello", 235L, "seconds", List.of())),
                    new RestStatusToXContentListener(channel));
        };
    }


    @Override
    public Set<String> responseParams() {
        return Set.of(MONITOR_ID);
    }
}
