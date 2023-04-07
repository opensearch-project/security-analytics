/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.resthandler;

import java.io.IOException;
import java.util.List;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.action.ExternalSourceRuleImportAction;
import org.opensearch.securityanalytics.action.ExternalSourceRuleImportRequest;
import org.opensearch.securityanalytics.action.GetMappingsViewAction;
import org.opensearch.securityanalytics.action.GetMappingsViewRequest;

import static java.util.Collections.singletonList;
import static org.opensearch.rest.RestRequest.Method.POST;

public class RestExternalSourceRuleImportAction extends BaseRestHandler {

    @Override
    public String getName() {
        return "external_source_rule_import_action";
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

        ExternalSourceRuleImportRequest req;
        if (!request.hasContentOrSourceParam()) {
            req = new ExternalSourceRuleImportRequest(
                request.param(ExternalSourceRuleImportRequest.SOURCE_ID)
            );
        } else {
            try (XContentParser parser = request.contentOrSourceParamParser()) {
                req = ExternalSourceRuleImportRequest.parse(parser);
            }
        }
        return channel -> client.execute(
                ExternalSourceRuleImportAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }

    @Override
    public List<Route> routes() {
        return singletonList(new Route(POST, SecurityAnalyticsPlugin.EXTERNAL_SOURCE_RULE_IMPORT_BASE_URI));
    }
}
