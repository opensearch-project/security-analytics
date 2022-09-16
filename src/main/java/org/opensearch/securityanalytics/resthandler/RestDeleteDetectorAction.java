/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.DeleteDetectorAction;
import org.opensearch.securityanalytics.action.DeleteDetectorRequest;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.securityanalytics.util.RestHandlerUtils.REFRESH;

public class RestDeleteDetectorAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestDeleteDetectorAction.class);

    @Override
    public String getName() {
        return "delete_detector_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.DELETE, String.format(Locale.getDefault(), "%s/{detectorID}", SecurityAnalyticsPlugin.DETECTOR_BASE_URI))
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s/{detectorID}", request.method(), SecurityAnalyticsPlugin.DETECTOR_BASE_URI));

        String detectorID = request.param("detectorID");
        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.parse(request.param(REFRESH, WriteRequest.RefreshPolicy.IMMEDIATE.getValue()));
        DeleteDetectorRequest deleteDetectorRequest = new DeleteDetectorRequest(detectorID, refreshPolicy);
        return channel -> client.execute(DeleteDetectorAction.INSTANCE, deleteDetectorRequest, new RestToXContentListener<>(channel));
    }
}