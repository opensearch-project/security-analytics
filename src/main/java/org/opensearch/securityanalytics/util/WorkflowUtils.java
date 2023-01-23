/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

public class WorkflowUtils {
    private static final Logger log = LogManager.getLogger(WorkflowUtils.class);
    private final Client client;

    private final MonitorUtils monitorUtils;

    public WorkflowUtils(Client client, MonitorUtils monitorUtils) {
        this.client = client;
        this.monitorUtils = monitorUtils;
    }

    public void upsertWorkflow(
        List<IndexMonitorResponse> monitors,
        Detector detector,
        RefreshPolicy refreshPolicy,
        String workflowId,
        Method method,
        ActionListener<IndexWorkflowResponse> listener
    ) {
        IndexWorkflowRequest indexWorkflowRequest = createWorkflowRequest(monitors,
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
                    List<String> monitorIds = monitors.stream().map(IndexMonitorResponse::getId).collect(
                        Collectors.toList());
                    log.error("Failed workflow creation. Removing created monitors: " + monitorIds.stream().collect(
                        Collectors.joining()) , e);

                    monitorUtils.deleteAlertingMonitors(monitorIds,
                        refreshPolicy,
                        new ActionListener<>() {
                            @Override
                            public void onResponse(List<DeleteMonitorResponse> deleteMonitorResponses) {
                                listener.onFailure(e);
                            }

                            @Override
                            public void onFailure(Exception e) {
                                listener.onFailure(e);
                            }
                        });
                }
            });
    }

    public void deleteWorkflow(String workflowId, WriteRequest.RefreshPolicy refreshPolicy, ActionListener<DeleteWorkflowResponse> deleteWorkflowListener) {
        DeleteWorkflowRequest deleteWorkflowRequest = new DeleteWorkflowRequest(workflowId, refreshPolicy);
        AlertingPluginInterface.INSTANCE.deleteWorkflow((NodeClient) client, deleteWorkflowRequest, deleteWorkflowListener);
    }

    private IndexWorkflowRequest createWorkflowRequest(List<IndexMonitorResponse> monitorResponses, Detector detector, RefreshPolicy refreshPolicy, String workflowId, Method method) {
        AtomicInteger index = new AtomicInteger();
        // TODO - update chained findings
        List<Delegate> delegates = monitorResponses.stream().map(
            indexMonitorResponse -> new Delegate(index.incrementAndGet(), indexMonitorResponse.getId(), null)
        ).collect(Collectors.toList());

        Map<String, String> ruleIdMonitorIdMap = mapMonitorIds(monitorResponses);
        Sequence sequence = new Sequence(delegates, ruleIdMonitorIdMap);
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

