/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;
import org.opensearch.rest.action.RestResponseListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.securityanalytics.threatIntel.common.Constants.THREAT_INTEL_SOURCE_CONFIG_ID;

public class RestIndexTIFSourceConfigAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestIndexTIFSourceConfigAction.class);
    @Override
    public String getName() {
        return "index_tif_config_action";
    }
    @Override
    public List<Route> routes() {
        return List.of(
                new Route(RestRequest.Method.POST, SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI),
                new Route(RestRequest.Method.PUT, String.format(Locale.getDefault(), "%s/{%s}",
                        SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, THREAT_INTEL_SOURCE_CONFIG_ID))
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        log.debug(String.format(Locale.getDefault(), "%s %s", request.method(), SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI));

        String id = request.param(THREAT_INTEL_SOURCE_CONFIG_ID, null);

        XContentParser xcp = request.contentParser();
        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);

        SATIFSourceConfigDto tifConfig = SATIFSourceConfigDto.parse(xcp, id, null);

        SAIndexTIFSourceConfigRequest indexTIFConfigRequest = new SAIndexTIFSourceConfigRequest(id, request.method(), tifConfig);
        return channel -> client.execute(SAIndexTIFSourceConfigAction.INSTANCE, indexTIFConfigRequest, indexTIFConfigResponse(channel, request.method()));
    }

    private RestResponseListener<SAIndexTIFSourceConfigResponse> indexTIFConfigResponse(RestChannel channel, RestRequest.Method restMethod) {
        return new RestResponseListener<>(channel) {
            @Override
            public RestResponse buildResponse(SAIndexTIFSourceConfigResponse response) throws Exception {
                RestStatus returnStatus = RestStatus.CREATED;
                if (restMethod == RestRequest.Method.PUT) {
                    returnStatus = RestStatus.OK;
                }

                BytesRestResponse restResponse = new BytesRestResponse(returnStatus, response.toXContent(channel.newBuilder(), ToXContent.EMPTY_PARAMS));

                if (restMethod == RestRequest.Method.POST) {
                    String location = String.format(Locale.getDefault(), "%s/%s", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, response.getTIFConfigId());
                    restResponse.addHeader("Location", location);
                }
                return restResponse;
            }
        };
    }
}