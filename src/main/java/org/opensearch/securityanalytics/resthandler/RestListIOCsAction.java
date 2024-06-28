/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.common.Strings;
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
import java.time.DateTimeException;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

import static org.opensearch.securityanalytics.services.STIX2IOCFeedStore.getIocIndexAlias;

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

        // Table params
        String sortString = request.param("sortString", "name");
        String sortOrder = request.param("sortOrder", "asc");
        String missing = request.param("missing");
        int size = request.paramAsInt("size", 20);
        int startIndex = request.paramAsInt("startIndex", 0);
        String searchString = request.param("searchString", "");

        Table table = new Table(
                sortOrder,
                sortString,
                missing,
                size,
                startIndex,
                searchString
        );
        List<String> types = List.of(Strings.commaDelimitedListToStringArray(request.param(ListIOCsActionRequest.TYPE_FIELD, ListIOCsActionRequest.ALL_TYPES_FILTER)));
        List<String> feedIds = List.of(Strings.commaDelimitedListToStringArray(request.param(STIX2IOC.FEED_ID_FIELD, "")));

        ListIOCsActionRequest listRequest = new ListIOCsActionRequest(types, feedIds, table);

        return channel -> client.execute(ListIOCsAction.INSTANCE, listRequest, new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(ListIOCsActionResponse response) throws Exception {
                return new BytesRestResponse(RestStatus.OK, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));
            }
        });
    }
}
