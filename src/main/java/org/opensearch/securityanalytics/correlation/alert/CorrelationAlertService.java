/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.alert;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.commons.alerting.model.CorrelationAlert;
import org.opensearch.securityanalytics.util.CorrelationIndices;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

public class CorrelationAlertService {
    private static final Logger log = LogManager.getLogger(CorrelationAlertService.class);

    private final NamedXContentRegistry xContentRegistry;
    private final Client client;

    public CorrelationAlertService(Client client, NamedXContentRegistry xContentRegistry) {
        this.client = client;
        this.xContentRegistry = xContentRegistry;
    }

    /**
     * Searches for active Alerts in the correlation alerts index within a specified time range.
     *
     * @param ruleId    The correlation rule ID to filter the alerts
     * @param currentTime The current time of the search range
     * @return The search response containing active alerts
     */
    public void getActiveAlerts(String ruleId, long currentTime, ActionListener<CorrelationAlertsList> listener) {
        Instant currentTimeDate = Instant.ofEpochMilli(currentTime);
        BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                .must(QueryBuilders.termQuery("correlation_rule_id", ruleId))
                .must(QueryBuilders.rangeQuery("start_time").lte(currentTimeDate))
                .must(QueryBuilders.rangeQuery("end_time").gte(currentTimeDate))
                .must(QueryBuilders.termQuery("state", "ACTIVE"));

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                .seqNoAndPrimaryTerm(true)
                .version(true)
                .size(10000) // set the size to 10,000
                .query(queryBuilder);

        SearchRequest searchRequest = new SearchRequest(CorrelationIndices.CORRELATION_ALERT_INDEX)
                .source(searchSourceBuilder);

        client.search(searchRequest, ActionListener.wrap(
                searchResponse -> {
                    if (searchResponse.getHits().getTotalHits().equals(0)) {
                        listener.onResponse(new CorrelationAlertsList(Collections.emptyList(), 0));
                    } else {
                        listener.onResponse(new CorrelationAlertsList(
                                parseCorrelationAlerts(searchResponse),
                                searchResponse.getHits() != null && searchResponse.getHits().getTotalHits() != null ?
                                        (int) searchResponse.getHits().getTotalHits().value : 0)
                        );
                    }
                },
                e -> {
                    log.error("Search request to fetch correlation alerts failed", e);
                    listener.onFailure(e);
                }
        ));
    }

    public void indexCorrelationAlert(CorrelationAlert correlationAlert, TimeValue indexTimeout, ActionListener<IndexResponse> listener) {
        // Convert CorrelationAlert to a map
        try {
            XContentBuilder builder = XContentFactory.jsonBuilder().startObject();
            builder.field("correlated_finding_ids", correlationAlert.getCorrelatedFindingIds());
            builder.field("correlation_rule_id", correlationAlert.getCorrelationRuleId());
            builder.field("correlation_rule_name", correlationAlert.getCorrelationRuleName());
            builder.field("id", correlationAlert.getId());
            builder.field("user", correlationAlert.getUser()); // Convert User object to map
            builder.field("schema_version", correlationAlert.getSchemaVersion());
            builder.field("severity", correlationAlert.getSeverity());
            builder.field("state", correlationAlert.getState());
            builder.field("trigger_name", correlationAlert.getTriggerName());
            builder.field("version", correlationAlert.getVersion());
            builder.field("start_time", correlationAlert.getStartTime());
            builder.field("end_time", correlationAlert.getEndTime());
            builder.field("action_execution_results", correlationAlert.getActionExecutionResults());
            builder.field("error_message", correlationAlert.getErrorMessage());
            builder.field("acknowledged_time", correlationAlert.getAcknowledgedTime());
            builder.endObject();
            IndexRequest indexRequest = new IndexRequest(CorrelationIndices.CORRELATION_ALERT_INDEX)
                    .id(correlationAlert.getId())
                    .source(builder)
                    .timeout(indexTimeout);

            client.index(indexRequest, listener);
        } catch (IOException ex) {
            log.error("Exception while adding alerts in .opensearch-sap-correlation-alerts index", ex);
        }
    }

    public List<CorrelationAlert> parseCorrelationAlerts(final SearchResponse response) throws IOException {
        List<CorrelationAlert> alerts = new ArrayList<>();
        for (SearchHit hit : response.getHits()) {
            XContentParser xcp = XContentType.JSON.xContent().createParser(
                    xContentRegistry,
                    LoggingDeprecationHandler.INSTANCE,
                    hit.getSourceAsString()
            );

            CorrelationAlert correlationAlert = CorrelationAlert.parse(xcp, hit.getId(), hit.getVersion());
            alerts.add(correlationAlert);
        }
        return alerts;
    }
    // Helper method to convert User object to map
}



