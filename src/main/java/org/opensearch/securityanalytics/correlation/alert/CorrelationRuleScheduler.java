package org.opensearch.securityanalytics.correlation.alert;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.securityanalytics.correlation.alert.notifications.NotificationService;
import org.opensearch.securityanalytics.model.CorrelationQuery;
import org.opensearch.securityanalytics.model.CorrelationRule;
import org.opensearch.securityanalytics.model.CorrelationRuleTrigger;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class CorrelationRuleScheduler {

    private static final Logger log = LogManager.getLogger(CorrelationRuleScheduler.class);

    public void schedule(List<CorrelationRule> correlationRules, Map<String, List<String>> correlatedFindings, String sourceFinding) {
        // Create a map of correlation rule to list of finding IDs
        Map<CorrelationRule, List<String>> correlationRuleToFindingIds = new HashMap<>();
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
                correlationRuleToFindingIds.put(rule, findingIds);
                // Simulate generating matched correlation rule IDs on rolling time window basis
                scheduleRule(rule, findingIds);
            }
        }
    }
    public void scheduleRule(CorrelationRule correlationRule, List<String> findingIds) {
        Timer timer = new Timer();
        long startTime = Instant.now().toEpochMilli();
        long endTime = startTime + TimeUnit.MINUTES.toMillis(correlationRule.getCorrTimeWindow()); // Assuming time window is based on ruleId
//        timer.schedule(new RuleTask(this.correlationAlertService, this.notificationService, correlationRule, findingIds, startTime, endTime), 0, 60000); // Check every minute
    }

    static class RuleTask extends TimerTask {
        private final CorrelationAlertService alertService;
        private final NotificationService notificationService;
        private final CorrelationRule correlationRule;
        private final long startTime;
        private final long endTime;
        private final List<String> correlatedFindingIds;


        public RuleTask(CorrelationAlertService alertService, NotificationService notificationService, CorrelationRule correlationRule, List<String> correlatedFindingIds, long startTime, long endTime) {
            this.alertService = alertService;
            this.notificationService = notificationService;
            this.startTime = startTime;
            this.endTime = endTime;
            this.correlatedFindingIds = correlatedFindingIds;
            this.correlationRule = correlationRule;
        }

        @Override
        public void run() {
            long currentTime = Instant.now().toEpochMilli();
//            if (currentTime >= startTime && currentTime <= endTime) { // Within time window
//                try {
//                    List<String> activeAlertIds = alertService.getActiveAlertsList(correlationRule.getId(), startTime, endTime);
//                    if (activeAlertIds.isEmpty()) {
//                        Map<String, Object> correlationAlert = Map.of(
//                                "start_time", startTime,
//                                "end_time", endTime,
//                                "correlation_rule_id", correlationRule.getId(),
//                                "severity", correlationRule.getCorrelationTrigger().getSeverity()
//                                // add more fields;
//                        );
//                        alertService.indexAlert(correlationAlert);
//                        //notificationService.sendNotification(alert);
//                    } else {
//                        alertService.updateActiveAlerts(activeAlertIds);
//                    }
//                } catch (IOException e) {
//                    throw new RuntimeException(e);
//                }
//            }
        }
    }
}
