package org.opensearch.securityanalytics.threatIntel.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestActions;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.SARefreshTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.action.SARefreshTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import static org.opensearch.securityanalytics.threatIntel.common.Constants.THREAT_INTEL_SOURCE_CONFIG_ID;

public class RestRefreshTIFSourceConfigAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestRefreshTIFSourceConfigAction.class);

    @Override
    public String getName() {
        return "refresh_tif_config_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.POST, String.format(Locale.getDefault(), "%s/{%s}/_refresh", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, THREAT_INTEL_SOURCE_CONFIG_ID)));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String saTifSourceConfigId = request.param(THREAT_INTEL_SOURCE_CONFIG_ID, SATIFSourceConfigDto.NO_ID);

        if (saTifSourceConfigId == null || saTifSourceConfigId.isBlank()) {
            throw new IllegalArgumentException("missing id");
        }

        SARefreshTIFSourceConfigRequest req = new SARefreshTIFSourceConfigRequest(saTifSourceConfigId);

        return channel -> client.execute(
                SARefreshTIFSourceConfigAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }
}
