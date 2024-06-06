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
import org.opensearch.common.lucene.uid.Versions;
import org.opensearch.commons.alerting.model.ActionExecutionResult;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.authuser.User;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
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
            xcp.nextToken();
            CorrelationAlert correlationAlert = parse(xcp, hit.getId(), hit.getVersion());
            alerts.add(correlationAlert);
        }
        return alerts;
    }

    // logic will be moved to common-utils, once the parsing logic in common-utils is fixed
    public static CorrelationAlert parse(XContentParser xcp, String id, long version) throws IOException {
        // Parse additional CorrelationAlert-specific fields
        List<String> correlatedFindingIds = new ArrayList<>();
        String correlationRuleId = null;
        String correlationRuleName = null;
        User user = null;
        int schemaVersion = 0;
        String triggerName = null;
        Alert.State state = null;
        String errorMessage = null;
        String severity = null;
        List<ActionExecutionResult> actionExecutionResults = new ArrayList<>();
        Instant startTime = null;
        Instant endTime = null;
        Instant acknowledgedTime = null;

        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();
            switch (fieldName) {
                case CORRELATED_FINDING_IDS:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        correlatedFindingIds.add(xcp.text());
                    }
                    break;
                case CORRELATION_RULE_ID:
                    correlationRuleId = xcp.text();
                    break;
                case CORRELATION_RULE_NAME:
                    correlationRuleName = xcp.text();
                    break;
                case USER_FIELD:
                    user = (xcp.currentToken() == XContentParser.Token.VALUE_NULL) ? null : User.parse(xcp);
                    break;
                case ALERT_ID_FIELD:
                    id = xcp.text();
                    break;
                case ALERT_VERSION_FIELD:
                    version = xcp.longValue();
                    break;
                case SCHEMA_VERSION_FIELD:
                    schemaVersion = xcp.intValue();
                    break;
                case TRIGGER_NAME_FIELD:
                    triggerName = xcp.text();
                    break;
                case STATE_FIELD:
                    state = Alert.State.valueOf(xcp.text());
                    break;
                case ERROR_MESSAGE_FIELD:
                    errorMessage = xcp.textOrNull();
                    break;
                case SEVERITY_FIELD:
                    severity = xcp.text();
                    break;
                case ACTION_EXECUTION_RESULTS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        actionExecutionResults.add(ActionExecutionResult.parse(xcp));
                    }
                    break;
                case START_TIME_FIELD:
                    startTime = Instant.parse(xcp.text());
                    break;
                case END_TIME_FIELD:
                    endTime = Instant.parse(xcp.text());
                    break;
                case ACKNOWLEDGED_TIME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        acknowledgedTime = null;
                    } else {
                        acknowledgedTime = Instant.parse(xcp.text());
                    }
                    break;
            }
        }

            // Create and return CorrelationAlert object
            return new CorrelationAlert(
                    correlatedFindingIds,
                    correlationRuleId,
                    correlationRuleName,
                    id,
                    version,
                    schemaVersion,
                    user,
                    triggerName,
                    state,
                    startTime,
                    endTime,
                    acknowledgedTime,
                    errorMessage,
                    severity,
                    actionExecutionResults
            );
    }
}




