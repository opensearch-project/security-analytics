/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.ValidateRulesAction;
import org.opensearch.securityanalytics.action.ValidateRulesRequest;

import java.io.IOException;
import java.util.List;

public class RestValidateRulesAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestValidateRulesAction.class);

    @Override
    public String getName() {
        return "validate_rules_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.RULE_BASE_URI + "/validate")
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {


        ValidateRulesRequest req;
        try (XContentParser xcp = request.contentParser()) {
            XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
            req = ValidateRulesRequest.parse(xcp);
        }
        return channel -> client.execute(ValidateRulesAction.INSTANCE, req, new RestToXContentListener<>(channel));
    }
}