package org.opensearch.securityanalytics.threatIntel.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestActions;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.SAGetTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.action.SAGetTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.securityanalytics.threatIntel.common.Constants.THREAT_INTEL_SOURCE_CONFIG_ID;

public class RestGetTIFSourceConfigAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestGetTIFSourceConfigAction.class);

    @Override
    public String getName() {
        return "get_tif_config_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, String.format(Locale.getDefault(), "%s/{%s}", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, THREAT_INTEL_SOURCE_CONFIG_ID)));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String saTifSourceConfigId = request.param(THREAT_INTEL_SOURCE_CONFIG_ID, SATIFSourceConfigDto.NO_ID);

        if (saTifSourceConfigId == null || saTifSourceConfigId.isEmpty()) {
            throw new IllegalArgumentException("missing threat intel source config id");
        }

        SAGetTIFSourceConfigRequest req = new SAGetTIFSourceConfigRequest(saTifSourceConfigId, RestActions.parseVersion(request));

        return channel -> client.execute(
                SAGetTIFSourceConfigAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }
}
