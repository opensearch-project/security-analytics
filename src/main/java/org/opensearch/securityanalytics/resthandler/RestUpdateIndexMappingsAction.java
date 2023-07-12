/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsAction;
import org.opensearch.securityanalytics.action.UpdateIndexMappingsRequest;

import java.io.IOException;
import java.util.List;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.PUT;

public class RestUpdateIndexMappingsAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "index_mappings_update_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        UpdateIndexMappingsRequest req;
        if (!request.hasContentOrSourceParam()) {
            req = new UpdateIndexMappingsRequest(
                    request.param(UpdateIndexMappingsRequest.INDEX_NAME_FIELD),
                    request.param(UpdateIndexMappingsRequest.FIELD),
                    request.param(UpdateIndexMappingsRequest.ALIAS)
            );
        } else {
            try (XContentParser xcp = request.contentParser()) {
                XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
                req = UpdateIndexMappingsRequest.parse(xcp);
            }
        }

        return channel -> client.execute(
                UpdateIndexMappingsAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(PUT, SecurityAnalyticsPlugin.MAPPER_BASE_URI));
    }
}
