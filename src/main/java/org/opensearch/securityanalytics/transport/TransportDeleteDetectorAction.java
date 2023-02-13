/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.action.DeleteMonitorResponse;
import org.opensearch.commons.alerting.action.DeleteWorkflowResponse;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.DeleteDetectorAction;
import org.opensearch.securityanalytics.action.DeleteDetectorRequest;
import org.opensearch.securityanalytics.action.DeleteDetectorResponse;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.util.MonitorService;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.securityanalytics.util.WorkflowService;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.opensearch.securityanalytics.model.Detector.NO_VERSION;

public class TransportDeleteDetectorAction extends HandledTransportAction<DeleteDetectorRequest, DeleteDetectorResponse> {

    private static final Logger log = LogManager.getLogger(TransportDeleteDetectorAction.class);

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final WorkflowService workflowService;

    private final MonitorService monitorService;

    private final ThreadPool threadPool;

    @Inject
    public TransportDeleteDetectorAction(TransportService transportService, WorkflowService workflowService, MonitorService monitorService, Client client, ActionFilters actionFilters, NamedXContentRegistry xContentRegistry) {
        super(DeleteDetectorAction.NAME, transportService, actionFilters, DeleteDetectorRequest::new);
        this.client = client;
        this.workflowService = workflowService;
        this.monitorService = monitorService;
        this.xContentRegistry = xContentRegistry;
        this.threadPool = client.threadPool();
    }

    @Override
    protected void doExecute(Task task, DeleteDetectorRequest request, ActionListener<DeleteDetectorResponse> listener) {
        AsyncDeleteDetectorAction asyncAction = new AsyncDeleteDetectorAction(task, request, listener);
        asyncAction.start();
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
            // If detector doesn't have the workflows it means that older version of the plugin is used
            if (detector.isWorkflowSupported()) {
                // 1. Delete workflow
                workflowService.deleteWorkflow(detector.getWorkflowIds().get(0),
                    request.getRefreshPolicy(),
                    new ActionListener<>() {
                        @Override
                        public void onResponse(DeleteWorkflowResponse deleteWorkflowResponse) {
                            // 2. Delete related monitors
                            monitorService.deleteAlertingMonitors(detector.getMonitorIds(),
                                request.getRefreshPolicy(),
                                new ActionListener<>() {
                                    @Override
                                    public void onResponse(List<DeleteMonitorResponse> deleteMonitorResponses) {
                                        // 3. Delete detector
                                        deleteDetectorFromConfig(detector.getId(), request.getRefreshPolicy());
                                    }

                                    @Override
                                    public void onFailure(Exception e) {
                                        if (counter.compareAndSet(false, true)) {
                                            finishHim(null, e);
                                        }
                                    }
                                });
                        }

                        @Override
                        public void onFailure(Exception e) {
                            if (counter.compareAndSet(false, true)) {
                                finishHim(null, e);
                            }
                        }
                    });
            } else {
                // 1. Delete monitors
                monitorService.deleteAlertingMonitors(detector.getMonitorIds(),
                    request.getRefreshPolicy(),
                    new ActionListener<>() {
                        @Override
                        public void onResponse(List<DeleteMonitorResponse> deleteMonitorResponses) {
                            // 2. Delete detector
                            deleteDetectorFromConfig(detector.getId(), request.getRefreshPolicy());
                        }

                        @Override
                        public void onFailure(Exception e) {
                            if (counter.compareAndSet(false, true)) {
                                finishHim(null, e);
                            }
                        }
                    });
            }
        }

        private void deleteDetectorFromConfig(String detectorId, WriteRequest.RefreshPolicy refreshPolicy) {
            deleteDetector(detectorId, refreshPolicy,
                    new ActionListener<>() {
                        @Override
                        public void onResponse(DeleteResponse response) {
                            onOperation(response);
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