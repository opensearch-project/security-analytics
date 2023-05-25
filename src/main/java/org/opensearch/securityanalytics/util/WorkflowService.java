/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.DeleteMonitorResponse;
import org.opensearch.commons.alerting.action.DeleteWorkflowRequest;
import org.opensearch.commons.alerting.action.DeleteWorkflowResponse;
import org.opensearch.commons.alerting.action.IndexMonitorResponse;
import org.opensearch.commons.alerting.action.IndexWorkflowRequest;
import org.opensearch.commons.alerting.action.IndexWorkflowResponse;
import org.opensearch.commons.alerting.model.ChainedMonitorFindings;
import org.opensearch.commons.alerting.model.CompositeInput;
import org.opensearch.commons.alerting.model.Delegate;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Monitor.MonitorType;
import org.opensearch.commons.alerting.model.Sequence;
import org.opensearch.commons.alerting.model.Workflow;
import org.opensearch.commons.alerting.model.Workflow.WorkflowType;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.securityanalytics.model.Detector;

/**
 * Alerting common clas used for workflow manipulation
 */
public class WorkflowService {
    private static final Logger log = LogManager.getLogger(WorkflowService.class);
    private Client client;
    private MonitorService monitorService;

    public WorkflowService(Client client, MonitorService monitorService) {
        this.client = client;
        this.monitorService = monitorService;
    }

    /**
     * Upserts the workflow - depending on the method and lists forwarded; If the method is put and updated
     * If the workflow upsert failed, deleting monitors will be performed
     * @param addedMonitors monitors to be added
     * @param updatedMonitors monitors to be updated
     * @param detector detector for which monitors needs to be added/updated
     * @param refreshPolicy
     * @param workflowId
     * @param method http method POST/PUT
     * @param listener
     */
    public void upsertWorkflow(
        List<IndexMonitorResponse> addedMonitors,
        List<IndexMonitorResponse> updatedMonitors,
        Detector detector,
        RefreshPolicy refreshPolicy,
        String workflowId,
        Method method,
        ActionListener<IndexWorkflowResponse> listener
    ) {
        if (method != Method.POST && method != Method.PUT) {
            log.error(String.format("Method %s not supported when upserting the workflow", method.name()));
            listener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchException("Method not supported")));
            return;
        }

        List<Monitor> monitors = new ArrayList<>(addedMonitors.stream().map(IndexMonitorResponse::getMonitor).collect(
            Collectors.toList()));

        if (updatedMonitors != null && !updatedMonitors.isEmpty()) {
            monitors.addAll(updatedMonitors.stream().map(IndexMonitorResponse::getMonitor).collect(Collectors.toList()));
        }

        IndexWorkflowRequest indexWorkflowRequest = createWorkflowRequest(
            monitors,
            detector,
            refreshPolicy,
            workflowId,
            method
        );

        AlertingPluginInterface.INSTANCE.indexWorkflow((NodeClient) client,
            indexWorkflowRequest,
            new ActionListener<>() {
                @Override
                public void onResponse(IndexWorkflowResponse workflowResponse) {
                    listener.onResponse(workflowResponse);
                }

                @Override
                public void onFailure(Exception e) {
                    List<String> addedMonitorIds = addedMonitors.stream().map(IndexMonitorResponse::getId).collect(
                        Collectors.toList());
                    // Remove created monitors and fail creation of workflow
                    log.error("Failed workflow saving. Removing created monitors: " + addedMonitorIds.stream().collect(
                        Collectors.joining()) , e);

                    monitorService.deleteAlertingMonitors(addedMonitorIds,
                        refreshPolicy,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(List<DeleteMonitorResponse> deleteMonitorResponses) {
                                log.debug("Monitors successfully deleted");
                                listener.onFailure(e);
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error("Error deleting monitors", e);
                                listener.onFailure(e);
                            }
                        });
                }
            });
    }

    public void deleteWorkflow(String workflowId, ActionListener<DeleteWorkflowResponse> deleteWorkflowListener) {
        DeleteWorkflowRequest deleteWorkflowRequest = new DeleteWorkflowRequest(workflowId, false);
        AlertingPluginInterface.INSTANCE.deleteWorkflow((NodeClient) client, deleteWorkflowRequest, deleteWorkflowListener);
    }

    private IndexWorkflowRequest createWorkflowRequest(
        List<Monitor> monitors,
        Detector detector,
        RefreshPolicy refreshPolicy,
        String workflowId,
        Method method
    ) {
        // Figure out bucketLevelId - docLevelId pairs
        Map<String, String> chainedFindingsDelegatePairs = getChainedBucketLevelDocLevelPairs(monitors);

        AtomicInteger index = new AtomicInteger();

        // TODO - update chained findings
        List<Delegate> delegates = monitors.stream().map(
            monitor -> new Delegate(
                index.incrementAndGet(),
                monitor.getId(),
                // If the matching docLevel pair exists, take it and create a Delegate with chained finding
                chainedFindingsDelegatePairs.get(monitor.getId()) != null ? new ChainedMonitorFindings(chainedFindingsDelegatePairs.get(monitor.getId())) : null
            )
        ).collect(Collectors.toList());
        
        Sequence sequence = new Sequence(delegates);
        CompositeInput compositeInput = new CompositeInput(sequence);

        Workflow workflow = new Workflow(
            workflowId,
            Workflow.NO_VERSION,
            detector.getName(),
            detector.getEnabled(),
            detector.getSchedule(),
            detector.getLastUpdateTime(),
            detector.getEnabledTime(),
            WorkflowType.COMPOSITE,
            detector.getUser(),
            1,
            List.of(compositeInput),
            "security_analytics",
            Collections.emptyList()
        );

        return new IndexWorkflowRequest(
            workflowId,
            SequenceNumbers.UNASSIGNED_SEQ_NO,
            SequenceNumbers.UNASSIGNED_PRIMARY_TERM,
            refreshPolicy,
            method,
            workflow,
            null
        );
    }

    /**
     * Returns bucketLevelMonitorId-docLevelMonitorId chained monitor pairs used for creating chained delegates.
     * Both bucketLevel and docLevel monitors pairs have name in specific format: aggRuleId_bucket or aggRuleId_chainedFindings.
     * Knowing this, grouping by the base name will be done and monitor pair ids will be created
     *
     * @param monitors List of all monitors
     * @return bucketLevelMonitorId-docLevelMonitorId pairs
     */
    public Map<String, String> getChainedBucketLevelDocLevelPairs(List<Monitor> monitors) {
        // Filter out only bucket level monitors
        long bucketMonitorsPresent = monitors.stream().filter(
            monitor -> MonitorType.BUCKET_LEVEL_MONITOR == monitor.getMonitorType()
        ).count();
        Map<String, String> chainedFindingsDelegatePairs = new HashMap<>();

        // If bucket level monitors are present, figure out the paired doc level monitor based on it's name
        if (bucketMonitorsPresent > 0) {
            // Group bucket monitors by the base name (ruleId)
            Map<String, Monitor> bucketMonitorsByName = monitors.stream().filter(
                monitor -> MonitorType.BUCKET_LEVEL_MONITOR == monitor.getMonitorType()
            ).collect(Collectors.toMap(it -> it.getName().split(BucketMonitorUtils.BUCKET_MONITOR_NAME_SUFFIX)[0], Function.identity()));

             monitors.forEach(monitor -> {
                 String monitorName = monitor.getName();
                 // Skip the monitors that are not paired to the bucket monitors
                 if (!monitorName.contains(BucketMonitorUtils.DOC_MATCH_ALL_MONITOR_NAME_SUFFIX)) {
                     return;
                 }

                 String monitorBaseName = monitorName.split(BucketMonitorUtils.DOC_MATCH_ALL_MONITOR_NAME_SUFFIX)[0];

                 if (bucketMonitorHasDocMonitorPair(bucketMonitorsByName, monitorBaseName)) {
                     var bucketMonitor = bucketMonitorsByName.get(monitorBaseName);

                    chainedFindingsDelegatePairs.put(bucketMonitor.getId(), monitor.getId());
                }
             });

            if (chainedFindingsDelegatePairs.size() != bucketMonitorsPresent) {
                throw new RuntimeException("stevan - sashank - error");
            }
        }
        return chainedFindingsDelegatePairs;
    }

    /**
     * Does the opposite of the getChainedBucketLevelDocLevelPairs - inverts the map produced by the getChainedBucketLevelDocLevelPairs
     * @param monitors List of the monitors
     * @return docLevelMonitorId-bucketLevelMonitorId pairs
     */
    public Map<String, String> getChainedDocLeveBucketLevelPairs(List<Monitor> monitors) {
        // In order not to pollute the RuleId-MonitorId map, exclude the complementary doc level monitors
        return getChainedBucketLevelDocLevelPairs(monitors).entrySet().stream().collect(Collectors.toMap(Entry::getValue, Entry::getKey));
    }

    private static boolean bucketMonitorHasDocMonitorPair(
        Map<String, Monitor> bucketMonitorsByName,
        String monitorBaseName
    ) {
        return bucketMonitorsByName.get(monitorBaseName) != null;
    }

    private Map<String, String> mapMonitorIds(List<IndexMonitorResponse> monitorResponses) {
        return monitorResponses.stream().collect(
            Collectors.toMap(
                // In the case of bucket level monitors rule id is trigger id
                it -> {
                    if (MonitorType.BUCKET_LEVEL_MONITOR == it.getMonitor().getMonitorType()) {
                        return it.getMonitor().getTriggers().get(0).getId();
                    } else {
                        return Detector.DOC_LEVEL_MONITOR;
                    }
                },
                IndexMonitorResponse::getId
            )
        );
    }
}

