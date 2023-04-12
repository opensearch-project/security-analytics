/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.support.WriteRequest;
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
import org.opensearch.commons.alerting.model.CompositeInput;
import org.opensearch.commons.alerting.model.Delegate;
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

    public WorkflowService() {
    }

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
        List<String> addedMonitors,
        List<String> updatedMonitors,
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

        List<String> monitorIds = new ArrayList<>();
        monitorIds.addAll(addedMonitors);

        if (updatedMonitors != null && !updatedMonitors.isEmpty()) {
            monitorIds.addAll(updatedMonitors);
        }

        IndexWorkflowRequest indexWorkflowRequest = createWorkflowRequest(monitorIds,
            detector,
            refreshPolicy, workflowId, method);

        AlertingPluginInterface.INSTANCE.indexWorkflow((NodeClient) client,
            indexWorkflowRequest,
            new ActionListener<>() {
                @Override
                public void onResponse(IndexWorkflowResponse workflowResponse) {
                    listener.onResponse(workflowResponse);
                }

                @Override
                public void onFailure(Exception e) {
                    // Remove created monitors and fail creation of workflow
                    log.error("Failed workflow saving. Removing created monitors: " + addedMonitors.stream().collect(
                        Collectors.joining()) , e);

                    monitorService.deleteAlertingMonitors(addedMonitors,
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

    private IndexWorkflowRequest createWorkflowRequest(List<String> monitorIds, Detector detector, RefreshPolicy refreshPolicy, String workflowId, Method method) {
        AtomicInteger index = new AtomicInteger();

        // TODO - update chained findings
        List<Delegate> delegates = monitorIds.stream().map(
            monitorId -> new Delegate(index.incrementAndGet(), monitorId, null)
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
            "security_analytics"
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

