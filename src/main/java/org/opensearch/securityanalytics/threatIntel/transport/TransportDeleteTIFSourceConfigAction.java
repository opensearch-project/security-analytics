package org.opensearch.securityanalytics.threatIntel.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.securityanalytics.threatIntel.action.SADeleteTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.action.SADeleteTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.action.SADeleteTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigManagementService;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportDeleteTIFSourceConfigAction extends HandledTransportAction<SADeleteTIFSourceConfigRequest, SADeleteTIFSourceConfigResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportDeleteTIFSourceConfigAction.class);

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private final SATIFSourceConfigManagementService SaTifConfigService;

    @Inject
    public TransportDeleteTIFSourceConfigAction(TransportService transportService,
                                                ActionFilters actionFilters,
                                                ClusterService clusterService,
                                                final ThreadPool threadPool,
                                                final SATIFSourceConfigManagementService SaTifConfigService) {
        super(SADeleteTIFSourceConfigAction.NAME, transportService, actionFilters, SADeleteTIFSourceConfigRequest::new);
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.SaTifConfigService = SaTifConfigService;
    }

    @Override
    protected void doExecute(Task task, SADeleteTIFSourceConfigRequest request, ActionListener<SADeleteTIFSourceConfigResponse> actionListener) {
        SaTifConfigService.deleteTIFSourceConfig(request.getId(), ActionListener.wrap(
                response -> actionListener.onResponse(
                        new SADeleteTIFSourceConfigResponse(
                                request.getId(),
                                RestStatus.OK
                        )
                ), actionListener::onFailure)
        );
    }
}
