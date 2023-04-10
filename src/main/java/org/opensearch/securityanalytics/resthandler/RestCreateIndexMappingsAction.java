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
import org.opensearch.securityanalytics.action.CreateIndexMappingsAction;
import org.opensearch.securityanalytics.action.CreateIndexMappingsRequest;

import java.io.IOException;
import java.util.List;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.securityanalytics.action.CreateIndexMappingsRequest.PARTIAL_FIELD_DEFAULT_VALUE;

public class RestCreateIndexMappingsAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "index_mappings_create_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        CreateIndexMappingsRequest req;
        if (!request.hasContentOrSourceParam()) {
            req = new CreateIndexMappingsRequest(
                    request.param(CreateIndexMappingsRequest.INDEX_NAME_FIELD),
                    request.param(CreateIndexMappingsRequest.RULE_TOPIC_FIELD),
                    request.param(CreateIndexMappingsRequest.ALIAS_MAPPINGS_FIELD),
                    request.paramAsBoolean(CreateIndexMappingsRequest.PARTIAL_FIELD, PARTIAL_FIELD_DEFAULT_VALUE)
            );
        } else {
            try (XContentParser xcp = request.contentParser()) {
                XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
                req = CreateIndexMappingsRequest.parse(xcp);
            }
        }

        return channel -> client.execute(
                CreateIndexMappingsAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(POST, SecurityAnalyticsPlugin.MAPPER_BASE_URI));
    }
}
