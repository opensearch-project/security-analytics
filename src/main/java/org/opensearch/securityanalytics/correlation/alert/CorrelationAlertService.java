/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.alert;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.FieldSortBuilder;
import org.opensearch.search.sort.SortBuilders;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.securityanalytics.model.CorrelationAlert;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

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

    public void getCorrelationAlerts(ActionListener<CorrelationAlertsList> listener,
                                     Table table,
                                     String severityLevel,
                                     String alertState) {
        try {
            if (false == correlationAlertsIndexExists()) {
                listener.onResponse(new CorrelationAlertsList(Collections.emptyList(), 0L));
            } else {
                FieldSortBuilder sortBuilder = SortBuilders
                        .fieldSort(table.getSortString())
                        .order(SortOrder.fromString(table.getSortOrder()));
                if (null != table.getMissing() && false == table.getMissing().isEmpty()) {
                    sortBuilder.missing(table.getMissing());
                }
                BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery();

                if (false == Objects.equals(severityLevel, "ALL")) {
                    queryBuilder.filter(QueryBuilders.termQuery("severity", severityLevel));
                }
                if (false == Objects.equals(alertState, "ALL")) {
                    queryBuilder.filter(QueryBuilders.termQuery("state", alertState));
                }
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                        .version(true)
                        .seqNoAndPrimaryTerm(true)
                        .query(queryBuilder)
                        .sort(sortBuilder)
                        .size(table.getSize())
                        .from(table.getStartIndex());

                SearchRequest searchRequest = new SearchRequest(CORRELATION_ALERT_INDEX).source(searchSourceBuilder);
                client.search(searchRequest, ActionListener.wrap(
                        searchResponse -> {
                            if (0 == searchResponse.getHits().getHits().length) {
                                listener.onResponse(new CorrelationAlertsList(Collections.emptyList(), 0L));
                            } else {
                                listener.onResponse(
                                        new CorrelationAlertsList(
                                                parseCorrelationAlerts(searchResponse),
                                                searchResponse.getHits().getTotalHits().value)
                                );
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
