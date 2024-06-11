package org.opensearch.securityanalytics.threatIntel.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestToXContentListener;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.SADeleteTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.action.SADeleteTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

public class RestDeleteTIFSourceConfigAction extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(RestDeleteTIFSourceConfigAction.class);

    @Override
    public String getName() {
        return "delete_tif_config_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(RestRequest.Method.DELETE, String.format(Locale.getDefault(), "%s/{%s}", SecurityAnalyticsPlugin.THREAT_INTEL_SOURCE_URI, "source_config_id")));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        String SaTifSourceConfigId = request.param("source_config_id", SATIFSourceConfigDto.NO_ID);

        if (SaTifSourceConfigId == null || SaTifSourceConfigId.isEmpty()) {
            throw new IllegalArgumentException("missing id");
        }

        SADeleteTIFSourceConfigRequest req = new SADeleteTIFSourceConfigRequest(SaTifSourceConfigId);

        return channel -> client.execute(
                SADeleteTIFSourceConfigAction.INSTANCE,
                req,
                new RestToXContentListener<>(channel)
        );
    }
}
