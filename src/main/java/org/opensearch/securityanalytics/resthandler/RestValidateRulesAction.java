/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentParserUtils;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.RestStatus;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.CreateIndexMappingsRequest;
import org.opensearch.securityanalytics.action.IndexRuleAction;
import org.opensearch.securityanalytics.action.IndexRuleRequest;
import org.opensearch.securityanalytics.action.IndexRuleResponse;
import org.opensearch.securityanalytics.action.ValidateRulesAction;
import org.opensearch.securityanalytics.action.ValidateRulesRequest;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.util.RestHandlerUtils;

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