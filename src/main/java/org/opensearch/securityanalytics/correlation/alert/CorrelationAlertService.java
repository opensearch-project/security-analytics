/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.alert;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.client.Client;
import org.opensearch.common.lucene.uid.Versions;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermsQueryBuilder;
import org.opensearch.script.Script;
import org.opensearch.script.ScriptType;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.commons.alerting.model.CorrelationAlert;
import org.opensearch.search.sort.FieldSortBuilder;
import org.opensearch.search.sort.SortBuilders;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.securityanalytics.action.AckCorrelationAlertsResponse;
import org.opensearch.securityanalytics.action.GetCorrelationAlertsResponse;
import org.opensearch.securityanalytics.util.CorrelationIndices;
import org.opensearch.securityanalytics.util.CorrelationRuleIndices;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;

public class CorrelationAlertService {
    private static final Logger log = LogManager.getLogger(CorrelationAlertService.class);

    private final NamedXContentRegistry xContentRegistry;
    private final Client client;

    protected static final String CORRELATED_FINDING_IDS = "correlated_finding_ids";
    protected static final String CORRELATION_RULE_ID = "correlation_rule_id";
    protected static final String CORRELATION_RULE_NAME = "correlation_rule_name";
    protected static final String ALERT_ID_FIELD = "id";
    protected static final String SCHEMA_VERSION_FIELD = "schema_version";
    protected static final String ALERT_VERSION_FIELD = "version";
    protected static final String USER_FIELD = "user";
    protected static final String TRIGGER_NAME_FIELD = "trigger_name";
    protected static final String STATE_FIELD = "state";
    protected static final String START_TIME_FIELD = "start_time";
    protected static final String END_TIME_FIELD = "end_time";
    protected static final String ACKNOWLEDGED_TIME_FIELD = "acknowledged_time";
    protected static final String ERROR_MESSAGE_FIELD = "error_message";
    protected static final String SEVERITY_FIELD = "severity";
    protected static final String ACTION_EXECUTION_RESULTS_FIELD = "action_execution_results";
    protected static final String NO_ID = "";
    protected static final long NO_VERSION = Versions.NOT_FOUND;

    public CorrelationAlertService(Client client, NamedXContentRegistry xContentRegistry) {
        this.client = client;
        this.xContentRegistry = xContentRegistry;
    }

    /**
     * Searches for active Alerts in the correlation alerts index within a specified time range.
     *
     * @param ruleId    The correlation rule ID to filter the alerts
     * @param currentTime The current time of the search range
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

    public void getCorrelationAlerts(String ruleId, Table tableProp, ActionListener<GetCorrelationAlertsResponse> listener) {
        BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery();
        if (ruleId != null) {
            queryBuilder = QueryBuilders.boolQuery()
                    .must(QueryBuilders.termQuery("correlation_rule_id", ruleId));
        }

        FieldSortBuilder sortBuilder = SortBuilders
                .fieldSort(tableProp.getSortString())
                .order(SortOrder.fromString(tableProp.getSortOrder()));
        if (tableProp.getMissing() != null && !tableProp.getMissing().isEmpty()) {
            sortBuilder.missing(tableProp.getMissing());
        }

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                .version(true)
                .seqNoAndPrimaryTerm(true)
                .query(queryBuilder)
                .sort(sortBuilder)
                .size(tableProp.getSize())
                .from(tableProp.getStartIndex());

        SearchRequest searchRequest = new SearchRequest(CorrelationIndices.CORRELATION_ALERT_INDEX)
                .source(searchSourceBuilder);

        client.search(searchRequest, ActionListener.wrap(
                searchResponse -> {
                    if (searchResponse.getHits().getTotalHits().equals(0)) {
                        listener.onResponse(new GetCorrelationAlertsResponse(Collections.emptyList(), 0));
                    } else {
                        listener.onResponse(new GetCorrelationAlertsResponse(
                                parseCorrelationAlerts(searchResponse),
                                searchResponse.getHits() != null && searchResponse.getHits().getTotalHits() != null ?
                                        (int) searchResponse.getHits().getTotalHits().value : 0)
                        );
                    }
                },
                e -> {
                    log.error("Search request to fetch correlation alerts failed", e);
                    if (e instanceof IndexNotFoundException) {
                        listener.onResponse(new GetCorrelationAlertsResponse(Collections.emptyList(), 0));
                    } else {
                        listener.onFailure(e);
                    }
                }
        ));
    }

    public void acknowledgeAlerts(List<String> alertIds, ActionListener<AckCorrelationAlertsResponse> listener) {
        BulkRequest bulkRequest = new BulkRequest();
        List<CorrelationAlert> acknowledgedAlerts = new ArrayList<>();
        List<CorrelationAlert> failedAlerts = new ArrayList<>();

        TermsQueryBuilder termsQueryBuilder = QueryBuilders.termsQuery("id", alertIds);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(termsQueryBuilder);
        SearchRequest searchRequest = new SearchRequest(CorrelationIndices.CORRELATION_ALERT_INDEX)
                .source(searchSourceBuilder);

        // Execute the search request
        client.search(searchRequest, new ActionListener<SearchResponse>() {
            @Override
            public void onResponse(SearchResponse searchResponse) {
                // Iterate through the search hits
                for (SearchHit hit : searchResponse.getHits().getHits()) {
                    // Construct a script to update the document with the new state and acknowledgedTime
                    // Construct a script to update the document with the new state and acknowledgedTime
                    Script script = new Script(ScriptType.INLINE, "painless",
                            "ctx._source.state = params.state; ctx._source.acknowledged_time = params.time",
                            Map.of("state", Alert.State.ACKNOWLEDGED, "time", Instant.now()));
                    // Create an update request with the script
                    UpdateRequest updateRequest = new UpdateRequest(CorrelationIndices.CORRELATION_ALERT_INDEX, hit.getId())
                            .script(script);

                    // Add the update request to the bulk request
                    bulkRequest.add(updateRequest);

                    // Add the current alert to the acknowledged alerts list
                    try {
                        acknowledgedAlerts.add(getParsedCorrelationAlert(hit));
                    } catch (IOException e) {
                        log.error("Exception while acknowledging alerts: {}", e.toString());
                    }
                }

                // Check if there are any update requests in the bulk request
                if (!bulkRequest.requests().isEmpty()) {
                    // Execute the bulk request asynchronously
                    client.bulk(bulkRequest, new ActionListener<BulkResponse>() {
                        @Override
                        public void onResponse(BulkResponse bulkResponse) {
                            // Iterate through the bulk response to identify failed updates
                            for (BulkItemResponse itemResponse : bulkResponse.getItems()) {
                                if (itemResponse.isFailed()) {
                                    // If an update failed, add the corresponding alert to the failed alerts list
                                    failedAlerts.add(acknowledgedAlerts.get(itemResponse.getItemId()));
                                }
                            }
                            // Create and pass the CorrelationAckAlertsResponse to the listener
                            listener.onResponse(new AckCorrelationAlertsResponse(acknowledgedAlerts, failedAlerts));
                        }

                        @Override
                        public void onFailure(Exception e) {
                            // Handle failure
                            listener.onFailure(e);
                        }
                    });
                } else {
                    // If there are no update requests, return an empty response
                    listener.onResponse(new AckCorrelationAlertsResponse(acknowledgedAlerts, failedAlerts));
                }
            }

            @Override
            public void onFailure(Exception e) {
                // Handle failure
                listener.onFailure(e);
            }
        });
    }

    public void updateCorrelationAlertsWithError(String correlationRuleId) {
        BulkRequest bulkRequest = new BulkRequest();
        BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery()
                .must(QueryBuilders.termQuery("correlation_rule_id", correlationRuleId));
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder().query(queryBuilder);
        SearchRequest searchRequest = new SearchRequest(CorrelationIndices.CORRELATION_ALERT_INDEX)
                .source(searchSourceBuilder);

        // Execute the search request
        client.search(searchRequest, new ActionListener<SearchResponse>() {
            @Override
            public void onResponse(SearchResponse searchResponse) {
                // Iterate through the search hits
                for (SearchHit hit : searchResponse.getHits().getHits()) {
                    // Construct a script to update the document with the new state and error_message
                    Script script = new Script(ScriptType.INLINE, "painless",
                            "ctx._source.state = params.state; ctx._source.error_message = params.error_message",
                            Map.of("state", Alert.State.ERROR, "error_message", "The rule associated to this Alert is deleted"));
                    // Create an update request with the script
                    UpdateRequest updateRequest = new UpdateRequest(CorrelationIndices.CORRELATION_ALERT_INDEX, hit.getId())
                            .script(script);
                    // Add the update request to the bulk request
                    bulkRequest.add(updateRequest);
                    client.bulk(bulkRequest);
                }
            }
            @Override
            public void onFailure(Exception e) {
                log.error("Error updating the alerts with Error message for correlation ruleId: {}", correlationRuleId);
            }
        });
    }


    public List<CorrelationAlert> parseCorrelationAlerts(final SearchResponse response) throws IOException {
        List<CorrelationAlert> alerts = new ArrayList<>();
        for (SearchHit hit : response.getHits()) {
            CorrelationAlert correlationAlert = getParsedCorrelationAlert(hit);
            alerts.add(correlationAlert);
        }
        return alerts;
    }

    private CorrelationAlert getParsedCorrelationAlert(SearchHit hit) throws IOException {
        XContentParser xcp = XContentType.JSON.xContent().createParser(
                xContentRegistry,
                LoggingDeprecationHandler.INSTANCE,
                hit.getSourceAsString()
        );
        xcp.nextToken();
        CorrelationAlert correlationAlert = CorrelationAlertsList.parse(xcp, hit.getId(), hit.getVersion());
        return correlationAlert;
    }
    
}




