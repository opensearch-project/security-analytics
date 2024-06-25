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
import org.opensearch.securityanalytics.action.TestS3ConnectionAction;
import org.opensearch.securityanalytics.action.TestS3ConnectionRequest;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.securityanalytics.SecurityAnalyticsPlugin.TEST_S3_CONNECTION_URI;

public class RestTestS3ConnectionAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestTestS3ConnectionAction.class);


    @Override
    public String getName() {
        return "test_connection_s3";
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, TEST_S3_CONNECTION_URI)
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), TEST_S3_CONNECTION_URI));

        XContentParser xcp = request.contentParser();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);

        TestS3ConnectionRequest testRequest = TestS3ConnectionRequest.parse(xcp);

        return channel -> client.execute(TestS3ConnectionAction.INSTANCE, testRequest, new RestToXContentListener<>(channel));
    }
}
