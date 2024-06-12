/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.ListIOCsAction;
import org.opensearch.securityanalytics.action.ListIOCsActionRequest;
import org.opensearch.securityanalytics.action.ListIOCsActionResponse;
import org.opensearch.securityanalytics.commons.model.STIX2;
import org.opensearch.securityanalytics.model.STIX2IOC;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

public class RestListIOCsAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestListIOCsAction.class);

    public String getName() {
        return "list_iocs_action";
    }

    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.GET, SecurityAnalyticsPlugin.LIST_IOCS_URI)
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.ROOT, "%s %s", request.method(), SecurityAnalyticsPlugin.LIST_IOCS_URI));

        int startIndex = request.paramAsInt(ListIOCsActionRequest.START_INDEX_FIELD, 0);
        int size = request.paramAsInt(ListIOCsActionRequest.SIZE_FIELD, 10);
        String sortOrder = request.param(ListIOCsActionRequest.SORT_ORDER_FIELD, ListIOCsActionRequest.SortOrder.asc.toString());
        String sortString = request.param(ListIOCsActionRequest.SORT_STRING_FIELD, STIX2.NAME_FIELD);
        String search = request.param(ListIOCsActionRequest.SEARCH_FIELD, "");
        String type = request.param(ListIOCsActionRequest.TYPE_FIELD, ListIOCsActionRequest.ALL_TYPES_FILTER);

        ListIOCsActionRequest listRequest = new ListIOCsActionRequest(startIndex, size, sortOrder, sortString, search, type);

        return channel -> client.execute(ListIOCsAction.INSTANCE, listRequest, new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(ListIOCsActionResponse response) throws Exception {
                return new BytesRestResponse(RestStatus.OK, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
            }
        });
    }
}
