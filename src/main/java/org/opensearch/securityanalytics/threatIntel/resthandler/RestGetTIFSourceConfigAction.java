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

public class RestGetTIFSourceConfigAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestGetTIFSourceConfigAction.class);

    @Override
    public String getName() {
        return "get_tif_config_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, String.format(Locale.getDefault(), "%s/{%s}", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, SAGetTIFSourceConfigRequest.TIF_SOURCE_CONFIG_ID)));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String SaTifSourceConfigId = request.param(SAGetTIFSourceConfigRequest.TIF_SOURCE_CONFIG_ID, SATIFSourceConfigDto.NO_ID);

        if (SaTifSourceConfigId == null || SaTifSourceConfigId.isEmpty()) {
            throw new IllegalArgumentException("missing id");
        }

        SAGetTIFSourceConfigRequest req = new SAGetTIFSourceConfigRequest(SaTifSourceConfigId, RestActions.parseVersion(request));

        return channel -> client.execute(
                SAGetTIFSourceConfigAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }
}
