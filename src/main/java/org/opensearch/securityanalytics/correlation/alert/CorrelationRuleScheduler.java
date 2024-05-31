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

import java.time.Instant;
import java.util.UUID;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class CorrelationRuleScheduler {

    private final Logger log = LogManager.getLogger(CorrelationRuleScheduler.class);
    private final Client client;
    private final CorrelationAlertService correlationAlertService;
    private final ExecutorService executorService;

    public CorrelationRuleScheduler(Client client, CorrelationAlertService correlationAlertService) {
        this.client = client;
        this.correlationAlertService = correlationAlertService;
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
                scheduleRule(rule, findingIds, indexTimeout);
            }
        }
    }

    public void shutdown() {
        executorService.shutdown();
    }

    private void scheduleRule(CorrelationRule correlationRule, List<String> findingIds, TimeValue indexTimeout) {
        long startTime = Instant.now().toEpochMilli();
        long endTime = startTime + correlationRule.getCorrTimeWindow();
        executorService.submit(new RuleTask(correlationRule, findingIds, startTime, endTime, correlationAlertService, indexTimeout));
    }

    private class RuleTask implements Runnable {
        private final CorrelationRule correlationRule;
        private final long startTime;
        private final long endTime;
        private final List<String> correlatedFindingIds;
        private final CorrelationAlertService correlationAlertService;
        private final TimeValue indexTimeout;

        public RuleTask(CorrelationRule correlationRule, List<String> correlatedFindingIds, long startTime, long endTime, CorrelationAlertService correlationAlertService, TimeValue indexTimeout) {
            this.correlationRule = correlationRule;
            this.correlatedFindingIds = correlatedFindingIds;
            this.startTime = startTime;
            this.endTime = endTime;
            this.correlationAlertService = correlationAlertService;
            this.indexTimeout = indexTimeout;
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
                            } else {
                                for (CorrelationAlert correlationAlert: correlationAlertsList.getCorrelationAlertList()) {
                                    updateCorrelationAlert(correlationAlert);
                                }
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error("Failed to search active correlation alert", e);
                        }
                    });
                } catch (Exception e) {
                    log.error("Failed to fetch active alerts in the time window", e);
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

