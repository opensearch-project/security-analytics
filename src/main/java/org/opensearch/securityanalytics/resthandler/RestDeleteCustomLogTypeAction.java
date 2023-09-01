/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeAction;
import org.opensearch.securityanalytics.action.DeleteCustomLogTypeRequest;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.util.RestHandlerUtils;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

public class RestDeleteCustomLogTypeAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestDeleteCustomLogTypeAction.class);

    @Override
    public String getName() {
        return "delete_custom_log_type_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.DELETE, String.format(Locale.getDefault(),
                        "%s/{%s}",
                        SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI,
                        CustomLogType.CUSTOM_LOG_TYPE_ID_FIELD))
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.CUSTOM_LOG_TYPE_URI));

        WriteRequest.RefreshPolicy refreshPolicy = WriteRequest.RefreshPolicy.IMMEDIATE;
        if (request.hasParam(RestHandlerUtils.REFRESH)) {
            refreshPolicy = WriteRequest.RefreshPolicy.parse(request.param(RestHandlerUtils.REFRESH));
        }

        String id = request.param(CustomLogType.CUSTOM_LOG_TYPE_ID_FIELD);
        if (id == null) {
            throw new OpenSearchStatusException("Log Type id is null", RestStatus.BAD_REQUEST);
        }

        DeleteCustomLogTypeRequest deleteCustomLogTypeRequest = new DeleteCustomLogTypeRequest(id, refreshPolicy);
        return channel -> client.execute(DeleteCustomLogTypeAction.INSTANCE, deleteCustomLogTypeRequest, new RestToXContentListener<>(channel));
    }
}