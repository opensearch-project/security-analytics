/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.StepListener;
import org.opensearch.common.SetOnce;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.DeleteMonitorRequest;
import org.opensearch.commons.alerting.action.DeleteMonitorResponse;
import org.opensearch.commons.alerting.action.DeleteWorkflowResponse;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.extensions.AcknowledgedResponse;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.DeleteDetectorAction;
import org.opensearch.securityanalytics.action.DeleteDetectorRequest;
import org.opensearch.securityanalytics.action.DeleteDetectorResponse;
import org.opensearch.securityanalytics.mapper.IndexTemplateManager;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.util.MonitorService;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.securityanalytics.util.WorkflowService;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;


import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class TransportDeleteDetectorAction extends HandledTransportAction<DeleteDetectorRequest, DeleteDetectorResponse> {

    private static final Logger log = LogManager.getLogger(TransportDeleteDetectorAction.class);

    private final Client client;

    private final RuleTopicIndices ruleTopicIndices;

    private final NamedXContentRegistry xContentRegistry;

    private final WorkflowService workflowService;

    private final MonitorService monitorService;

    private final ThreadPool threadPool;

    private final IndexTemplateManager indexTemplateManager;

    @Inject
    public TransportDeleteDetectorAction(TransportService transportService, IndexTemplateManager indexTemplateManager, Client client, ActionFilters actionFilters, NamedXContentRegistry xContentRegistry, RuleTopicIndices ruleTopicIndices) {
        super(DeleteDetectorAction.NAME, transportService, actionFilters, DeleteDetectorRequest::new);
        this.client = client;
        this.ruleTopicIndices = ruleTopicIndices;
        this.xContentRegistry = xContentRegistry;
        this.threadPool = client.threadPool();
        this.indexTemplateManager = indexTemplateManager;
        this.monitorService = new MonitorService(client);
        this.workflowService = new WorkflowService(client, monitorService);

    }

    @Override
    protected void doExecute(Task task, DeleteDetectorRequest request, ActionListener<DeleteDetectorResponse> listener) {
        AsyncDeleteDetectorAction asyncAction = new AsyncDeleteDetectorAction(task, request, listener);
        asyncAction.start();
    }

    private void deleteAlertingMonitor(String monitorId, WriteRequest.RefreshPolicy refreshPolicy, ActionListener<DeleteMonitorResponse> listener) {
        DeleteMonitorRequest request = new DeleteMonitorRequest(monitorId, refreshPolicy);
        AlertingPluginInterface.INSTANCE.deleteMonitor((NodeClient) client, request, listener);
    }

    private void deleteDetector(String detectorId, WriteRequest.RefreshPolicy refreshPolicy, ActionListener<DeleteResponse> listener) {
        DeleteRequest request = new DeleteRequest(Detector.DETECTORS_INDEX, detectorId)
                .setRefreshPolicy(refreshPolicy);
        client.delete(request, listener);
    }

    class AsyncDeleteDetectorAction {
        private final DeleteDetectorRequest request;

        private final ActionListener<DeleteDetectorResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;

        AsyncDeleteDetectorAction(Task task, DeleteDetectorRequest request, ActionListener<DeleteDetectorResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;

            this.response = new AtomicReference<>();
        }

        void start() {
            TransportDeleteDetectorAction.this.threadPool.getThreadContext().stashContext();
            String detectorId = request.getDetectorId();
            GetRequest getRequest = new GetRequest(Detector.DETECTORS_INDEX, detectorId);
            client.get(getRequest,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(GetResponse response) {
                            if (!response.isExists()) {
                                onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Detector with %s is not found", detectorId), RestStatus.NOT_FOUND));
                                return;
                            }

                            try {
                                XContentParser xcp = XContentHelper.createParser(xContentRegistry, LoggingDeprecationHandler.INSTANCE,
                                        response.getSourceAsBytesRef(), XContentType.JSON);
                                Detector detector = Detector.docParse(xcp, response.getId(), response.getVersion());
                                onGetResponse(detector);
                            } catch (Exception e) {
                                onFailures(e);
                            }
                        }

                        @Override
                        public void onFailure(Exception t) {
                            onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Detector with %s is not found", detectorId), RestStatus.NOT_FOUND));
                        }
                    });
        }

        private void onGetResponse(Detector detector) {
            StepListener<AcknowledgedResponse> onDeleteWorkflowStep = new StepListener<>();
            // 1. Delete the workflow if the workflow is supported
            deleteWorkflow(detector, onDeleteWorkflowStep);
            onDeleteWorkflowStep.whenComplete(acknowledgedResponse -> {
                log.debug(
                    String.format("Workflow deleted. Deleting the monitors %s before detector deletion",
                        detector.getMonitorIds().stream().collect(Collectors.joining(",")))
                );
                // 2. Delete alerting monitors
                StepListener<List<DeleteMonitorResponse>> onDeleteMonitorsStep = new StepListener<>();
                monitorService.deleteAlertingMonitors(detector.getMonitorIds(),
                    request.getRefreshPolicy(), onDeleteMonitorsStep);

                onDeleteMonitorsStep.whenComplete(deleteMonitorResponses -> {
                    log.debug(
                        String.format("Monitors deleted. Deleting the detector %s", detector.getId())
                    );
                    // 3. Delete detector
                    deleteDetectorFromConfig(detector.getId(), request.getRefreshPolicy());
                }, e -> {
                    if (counter.compareAndSet(false, true)) {
                        finishHim(null, e);
                    }
                });
            }, e -> {
                if (counter.compareAndSet(false, true)) {
                    finishHim(null, e);
                }
            });
        }
        private void deleteWorkflow(Detector detector, ActionListener<AcknowledgedResponse> actionListener) {
            if (detector.isWorkflowSupported()) {
                var workflowId =  detector.getWorkflowIds().get(0);
                log.debug(String.format("Deleting the workflow %s before deleting the detector", workflowId));
                StepListener<DeleteWorkflowResponse> onDeleteWorkflowStep = new StepListener<>();
                workflowService.deleteWorkflow(workflowId, onDeleteWorkflowStep);
                onDeleteWorkflowStep.whenComplete(deleteWorkflowResponse -> {
                    actionListener.onResponse(new AcknowledgedResponse(true));
                }, actionListener::onFailure);
            } else {
                // If detector doesn't have the workflows it means that older version of the plugin is used and just skip the step
                actionListener.onResponse(new AcknowledgedResponse(true));
            }
        }

        private void deleteDetectorFromConfig(String detectorId, WriteRequest.RefreshPolicy refreshPolicy) {
            deleteDetector(detectorId, refreshPolicy,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(DeleteResponse response) {

                            indexTemplateManager.deleteAllUnusedTemplates(new ActionListener<Void>() {
                                @Override
                                public void onResponse(Void unused) {
                                    onOperation(response);
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    log.error("Error deleting unused templates: " + e.getMessage());
                                    onOperation(response);
                                }
                            });

                        }
                        @Override
                        public void onFailure(Exception t) {
                            onFailures(t);
                        }
                    });
        }

        private void onOperation(DeleteResponse response) {
            this.response.set(response);
            if (counter.compareAndSet(false, true)) {
                finishHim(response.getId(), null);
            }
        }

        private void onFailures(Exception t) {
            if (counter.compareAndSet(false, true)) {
                finishHim(null, t);
            }
        }

        private void finishHim(String detectorId, Exception t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null) {
                    if (t instanceof OpenSearchStatusException) {
                        throw t;
                    }
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return new DeleteDetectorResponse(detectorId, NO_VERSION, RestStatus.NO_CONTENT);
                }
            }));
        }
    }
}