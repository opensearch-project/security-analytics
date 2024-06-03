package org.opensearch.securityanalytics.correlation.alert;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.commons.alerting.model.Alert;
import org.opensearch.commons.alerting.model.CorrelationAlert;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.model.CorrelationQuery;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.model.CorrelationRuleTrigger;
import org.opensearch.securityanalytics.correlation.alert.notifications.NotificationService;
import org.opensearch.securityanalytics.correlation.alert.notifications.CorrelationAlertContext;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import java.time.Instant;
import java.util.UUID;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.opensearch.script.ScriptService;

public class CorrelationRuleScheduler {

    private final Logger log = LogManager.getLogger(CorrelationRuleScheduler.class);
    private final Client client;
    private final CorrelationAlertService correlationAlertService;
    private final NotificationService notificationService;
    private final ExecutorService executorService;
    private static ScriptService scriptService;

    public CorrelationRuleScheduler(Client client, CorrelationAlertService correlationAlertService, NotificationService notificationService) {
        this.client = client;
        this.scriptService = scriptService;
        this.correlationAlertService = correlationAlertService;
        this.notificationService = notificationService;
        this.executorService = Executors.newCachedThreadPool();
    }

    public void schedule(List<CorrelationRule> correlationRules, Map<String, List<String>> correlatedFindings, String sourceFinding, TimeValue indexTimeout) {
        for (CorrelationRule rule : correlationRules) {
            CorrelationRuleTrigger trigger = rule.getCorrelationTrigger();
            if (trigger != null) {
                List<String> findingIds = new ArrayList<>();
                for (CorrelationQuery query : rule.getCorrelationQueries()) {
                    List<String> categoryFindingIds = correlatedFindings.get(query.getCategory());
                    if (categoryFindingIds != null) {
                        findingIds.addAll(categoryFindingIds);
                    }
                }
                scheduleRule(rule, findingIds, indexTimeout, sourceFinding);
            }
        }
    }

    public void shutdown() {
        executorService.shutdown();
    }

    private void scheduleRule(CorrelationRule correlationRule, List<String> findingIds, TimeValue indexTimeout, String sourceFindingId) {
        long startTime = Instant.now().toEpochMilli();
        long endTime = startTime + correlationRule.getCorrTimeWindow();
        RuleTask ruleTask = new RuleTask(correlationRule, findingIds, startTime, endTime, correlationAlertService, notificationService, indexTimeout, sourceFindingId);
        executorService.submit(ruleTask);
    }

    private class RuleTask implements Runnable {
        private final CorrelationRule correlationRule;
        private final long startTime;
        private final long endTime;
        private final List<String> correlatedFindingIds;
        private final CorrelationAlertService correlationAlertService;
        private final NotificationService notificationService;
        private final TimeValue indexTimeout;
        private final String sourceFindingId;

        public RuleTask(CorrelationRule correlationRule, List<String> correlatedFindingIds, long startTime, long endTime, CorrelationAlertService correlationAlertService, NotificationService notificationService, TimeValue indexTimeout, String sourceFindingId) {
            this.correlationRule = correlationRule;
            this.correlatedFindingIds = correlatedFindingIds;
            this.startTime = startTime;
            this.endTime = endTime;
            this.correlationAlertService = correlationAlertService;
            this.notificationService = notificationService;
            this.indexTimeout = indexTimeout;
            this.sourceFindingId = sourceFindingId;
        }

        @Override
        public void run() {
            long currentTime = Instant.now().toEpochMilli();
            if (currentTime >= startTime && currentTime <= endTime) {
                try {
                    correlationAlertService.getActiveAlerts(correlationRule.getId(), currentTime, new ActionListener<>() {
                        @Override
                        public void onResponse(CorrelationAlertsList correlationAlertsList) {
                            if (correlationAlertsList.getTotalAlerts() == 0) {
                                addCorrelationAlertIntoIndex();
                                List<Action> actions = correlationRule.getCorrelationTrigger().getActions();
                                for (Action action : actions) {
                                    CorrelationAlertContext ctx = new CorrelationAlertContext(correlatedFindingIds, correlationRule.getName(), correlationRule.getCorrTimeWindow(), sourceFindingId);
                                    String transfomedSubject = notificationService.compileTemplate(ctx, action.getSubjectTemplate());
                                    String transformedMessage = notificationService.compileTemplate(ctx, action.getMessageTemplate());
                                    try {
                                        notificationService.sendNotification(action.getDestinationId(), correlationRule.getCorrelationTrigger().getSeverity(), transfomedSubject, transformedMessage);
                                    } catch (Exception e) {
                                        log.error("Failed while sending a notification: " + e.toString());
                                        new SecurityAnalyticsException("Failed to send notification", RestStatus.INTERNAL_SERVER_ERROR, e);
                                    }

                                }
                            } else {
                                for (CorrelationAlert correlationAlert: correlationAlertsList.getCorrelationAlertList()) {
                                    updateCorrelationAlert(correlationAlert);
                                }
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to search active correlation alert", e);
                            new SecurityAnalyticsException("Failed to search active correlation alert", RestStatus.INTERNAL_SERVER_ERROR, e);
                        }
                    });
                } catch (Exception e) {
                    log.error("Failed to fetch active alerts in the time window", e);
                    new SecurityAnalyticsException("Failed to get active alerts in the correlationRuletimewindow", RestStatus.INTERNAL_SERVER_ERROR, e);
                }
            }
        }

        private void addCorrelationAlertIntoIndex() {
            CorrelationAlert correlationAlert = new CorrelationAlert(
                    correlatedFindingIds,
                    correlationRule.getId(),
                    correlationRule.getName(),
                    UUID.randomUUID().toString(),
                    1L,
                    1,
                    null,
                    correlationRule.getCorrelationTrigger().getName(),
                    Alert.State.ACTIVE,
                    Instant.ofEpochMilli(startTime),
                    Instant.ofEpochMilli(endTime),
                    null,
                    null,
                    correlationRule.getCorrelationTrigger().getSeverity(),
                    new ArrayList<>()
            );
            insertCorrelationAlert(correlationAlert);
        }

        private void updateCorrelationAlert(CorrelationAlert correlationAlert) {
            CorrelationAlert newCorrelationAlert = new CorrelationAlert(
                    correlatedFindingIds,
                    correlationAlert.getCorrelationRuleId(),
                    correlationAlert.getCorrelationRuleName(),
                    correlationAlert.getId(),
                    1L,
                    1,
                    correlationAlert.getUser(),
                    correlationRule.getCorrelationTrigger().getName(),
                    Alert.State.ACTIVE,
                    Instant.ofEpochMilli(startTime),
                    Instant.ofEpochMilli(endTime),
                    null,
                    null,
                    correlationRule.getCorrelationTrigger().getSeverity(),
                    new ArrayList<>()
            );
           insertCorrelationAlert(newCorrelationAlert);
        }

        private void insertCorrelationAlert(CorrelationAlert correlationAlert) {
            correlationAlertService.indexCorrelationAlert(correlationAlert, indexTimeout, new ActionListener<>() {
                @Override
                public void onResponse(IndexResponse indexResponse) {
                    log.info("Successfully updated the index .opensearch-sap-correlation-alerts: {}", indexResponse);
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to index correlation alert", e);
                }
            });
        }
    }
}

