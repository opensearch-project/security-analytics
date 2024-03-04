package org.opensearch.securityanalytics.correlation.alert;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestResponse;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.model.CorrelationAlert;
import org.opensearch.securityanalytics.model.Detector;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.opensearch.core.rest.RestStatus.OK;

public class CorrelationAlertService {
    public static final String CORRELATION_ALERT_INDEX = ".opensearch-sap-correlations-alerts";
    private static final Logger log = LogManager.getLogger(CorrelationAlertService.class);
    private final Client client;
    private final ClusterService clusterService;
    private final NamedXContentRegistry xContentRegistry;

    public CorrelationAlertService(Client client, ClusterService clusterService, NamedXContentRegistry xContentRegistry) {
        this.client = client;
        this.clusterService = clusterService;
        this.xContentRegistry = xContentRegistry;
    }

    public void getCorrelationAlerts(ActionListener<List<CorrelationAlert>> listener) {
        try {
            if (false == correlationAlertsIndexExists()) {
                listener.onResponse(Collections.emptyList());
            } else {
                SearchRequest searchRequest = new SearchRequest(CORRELATION_ALERT_INDEX);
                client.search(searchRequest, ActionListener.wrap(
                        searchResponse -> {
                            if (0 == searchResponse.getHits().getHits().length) {
                                listener.onResponse(Collections.emptyList());
                            } else {
                                listener.onResponse(parseCorrelationAlerts(searchResponse));
                            }
                        },
                        e -> {
                            log.error("Search request to fetch correlation alerts failed", e);
                            listener.onFailure(e);
                        }
                ));
            }
        } catch (Exception e) {
            log.error("Unexpected error when fetch correlation alerts", e);
            listener.onFailure(e);
        }
    }

    public boolean correlationAlertsIndexExists() {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(CORRELATION_ALERT_INDEX);
    }

    public List<CorrelationAlert> parseCorrelationAlerts(final SearchResponse response) throws IOException {
        List<CorrelationAlert> alerts = new ArrayList<>();
        for (SearchHit hit : response.getHits()) {
            XContentParser xcp = XContentType.JSON.xContent().createParser(
                    xContentRegistry,
                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString());
            CorrelationAlert correlationAlert = CorrelationAlert.docParse(xcp, hit.getId(), hit.getVersion());
            alerts.add(correlationAlert);
        }
        return alerts;
    }
}
