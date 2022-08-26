/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.resthandlers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.commons.model2.action.ExecuteMonitorAction;
import org.opensearch.commons.model2.action.ExecuteMonitorRequest;
import org.opensearch.commons.model2.model.Monitor;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.securityanalytics.Tokens.*;

public class RestExecuteMonitorAction extends BaseRestHandler {

    private static final Logger LOG = LogManager.getLogger(RestExecuteMonitorAction.class);

    @Override
    public String getName() {
        return "ex_monitor_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, SAP_MONITORS_BASE_URI + "/{" + MONITOR_ID + "}/_execute"));
    }

    @Override

    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        return channel -> {
            LOG.info("{} {}/{}", request.method(), SAP_MONITORS_BASE_URI, getName());
            final String monitorId = request.param(MONITOR_ID);
            final TimeValue requestEnd = request.paramAsTime(REQUEST_END, TimeValue.MAX_VALUE);
            final boolean dryRun = request.paramAsBoolean(DRY_RUN, false);
            if (null == monitorId || monitorId.isEmpty()) throw new IllegalArgumentException("missing monitorID");
            client.execute(ExecuteMonitorAction.SAP_INSTANCE, new ExecuteMonitorRequest(new Monitor("1334", "good", 1L, null, "hello", 45L, "seconds", List.of())), new RestToXContentListener<>(channel));
        };
    }


    @Override
    public Set<String> responseParams() {
        return Set.of(MONITOR_ID);
    }
}
