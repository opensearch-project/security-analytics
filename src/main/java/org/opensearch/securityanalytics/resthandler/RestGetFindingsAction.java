/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import java.io.IOException;
import java.util.List;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.action.AlertingActions;
import org.opensearch.commons.alerting.action.GetFindingsRequest;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;


import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.GET;

public class RestGetFindingsAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "get_findings_sa";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        String findingID = request.param("findingId");
        String sortString = request.param("sortString", "id");
        String sortOrder = request.param("sortOrder", "asc");
        String missing = request.param("missing");
        Integer size = request.paramAsInt("size", 20);
        Integer startIndex = request.paramAsInt("startIndex", 0);
        String searchString = request.param("searchString", "");
        String monitorId = request.param("monitorId", null);
        String findingIndex = request.param("findingIndex", null);

        Table table = new Table(
            sortOrder,
            sortString,
            missing,
            size,
            startIndex,
            searchString
        );

        GetFindingsRequest req = new GetFindingsRequest(
            findingID,
            table,
            monitorId,
            findingIndex
        );

        return channel -> client.execute(
                AlertingActions.GET_FINDINGS_ACTION_TYPE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(GET, SecurityAnalyticsPlugin.FINDINGS_BASE_URI));
    }
}
