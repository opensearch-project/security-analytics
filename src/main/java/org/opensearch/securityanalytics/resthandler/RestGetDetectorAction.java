/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestActions;
import org.opensearch.rest.action.RestToXContentListener;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;
import static org.opensearch.rest.RestRequest.Method.GET;


import org.opensearch.securityanalytics.action.GetDetectorAction;
import org.opensearch.securityanalytics.action.GetDetectorRequest;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;

public class RestGetDetectorAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestGetDetectorAction.class);

    @Override
    public String getName() {
        return "get_detector_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, String.format(Locale.getDefault(), "%s/{%s}", SecurityAnalyticsPlugin.DETECTOR_BASE_URI, GetDetectorRequest.DETECTOR_ID)));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String detectorId = request.param(GetDetectorRequest.DETECTOR_ID, Detector.NO_ID);

        if (detectorId == null || detectorId.isEmpty()) {
            throw new IllegalArgumentException("missing id");
        }

        GetDetectorRequest req = new GetDetectorRequest(detectorId, RestActions.parseVersion(request));

        return channel -> client.execute(
                GetDetectorAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }
}