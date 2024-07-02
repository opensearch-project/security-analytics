package org.opensearch.securityanalytics.threatIntel.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.securityanalytics.threatIntel.action.SADeleteTIFSourceConfigAction;
import org.opensearch.securityanalytics.threatIntel.action.SADeleteTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.action.SADeleteTIFSourceConfigResponse;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigManagementService;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

public class TransportDeleteTIFSourceConfigAction extends HandledTransportAction<SADeleteTIFSourceConfigRequest, SADeleteTIFSourceConfigResponse> implements SecureTransportAction {

    private static final Logger log = LogManager.getLogger(TransportDeleteTIFSourceConfigAction.class);

    private final SATIFSourceConfigManagementService saTifConfigService;

    @Inject
    public TransportDeleteTIFSourceConfigAction(TransportService transportService,
                                                ActionFilters actionFilters,
                                                final SATIFSourceConfigManagementService saTifConfigService) {
        super(SADeleteTIFSourceConfigAction.NAME, transportService, actionFilters, SADeleteTIFSourceConfigRequest::new);
        this.saTifConfigService = saTifConfigService;
    }

    @Override
    protected void doExecute(Task task, SADeleteTIFSourceConfigRequest request, ActionListener<SADeleteTIFSourceConfigResponse> actionListener) {
        saTifConfigService.deleteTIFSourceConfig(request.getId(), ActionListener.wrap(
                response -> actionListener.onResponse(
                        new SADeleteTIFSourceConfigResponse(
                                request.getId(),
                                response.status()
                        )
                ), e -> {
                    log.error("Failed to delete threat intel source config [{}] ", request.getId());
                    actionListener.onFailure(e);
                })
        );
    }
}
