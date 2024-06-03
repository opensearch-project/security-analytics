package org.opensearch.securityanalytics.threatIntel.transport.monitor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.IndexMonitorRequest;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.DocLevelMonitorInput;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.monitor.IndexThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.IndexThreatIntelMonitorRequest;
import org.opensearch.securityanalytics.threatIntel.action.monitor.response.IndexThreatIntelMonitorResponse;
import org.opensearch.securityanalytics.threatIntel.iocscan.dto.PerIocTypeScanInput;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.opensearch.securityanalytics.transport.TransportIndexDetectorAction.PLUGIN_OWNER_FIELD;

public class TransportIndexThreatIntelMonitorAction extends HandledTransportAction<IndexThreatIntelMonitorRequest, IndexThreatIntelMonitorResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(TransportIndexThreatIntelMonitorAction.class);

    private final ThreadPool threadPool;
    private final Settings settings;
    private final NamedWriteableRegistry namedWriteableRegistry;
    private final Client client;
    private volatile Boolean filterByEnabled;
    private final TimeValue indexTimeout;

    @Inject
    public TransportIndexThreatIntelMonitorAction(
            final TransportService transportService,
            final ActionFilters actionFilters,
            final ThreadPool threadPool,
            final Settings settings,
            final Client client,
            final NamedWriteableRegistry namedWriteableRegistry
    ) {
        super(IndexThreatIntelMonitorAction.NAME, transportService, actionFilters, IndexThreatIntelMonitorRequest::new);
        this.threadPool = threadPool;
        this.settings = settings;
        this.namedWriteableRegistry = namedWriteableRegistry;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, IndexThreatIntelMonitorRequest request, ActionListener<IndexThreatIntelMonitorResponse> listener) {
        // validate user
        User user = readUserFromThreadContext(this.threadPool);
        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException(validateBackendRoleMessage, RestStatus.FORBIDDEN)));
            return;
        }
        //create
        String id = request.getMethod() == RestRequest.Method.POST ? Monitor.NO_ID : request.getId();
        IndexMonitorRequest indexMonitorRequest = new IndexMonitorRequest(
                id,
                SequenceNumbers.UNASSIGNED_SEQ_NO,
                SequenceNumbers.UNASSIGNED_PRIMARY_TERM,
                WriteRequest.RefreshPolicy.IMMEDIATE,
                request.getMethod(),
                getMonitor(request),
                null
        );
        AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, indexMonitorRequest, namedWriteableRegistry, ActionListener.wrap(
                r -> {
                    listener.onResponse(new IndexThreatIntelMonitorResponse(r.getId(), r.getVersion(), r.getSeqNo(), r.getPrimaryTerm(),
                            new ThreatIntelMonitorDto(
                                    r.getId(),
                                    r.getMonitor().getName(),
                                    request.getThreatIntelMonitor().getPerIocTypeScanInputList(),
                                    r.getMonitor().getSchedule(),
                                    r.getMonitor().getEnabled(),
                                    user)
                    ));
                }, e -> {
                    log.error("failed to creat custom monitor", e);
                    listener.onFailure(e);
                }
        ));
    }

    private static Monitor getMonitor(IndexThreatIntelMonitorRequest request) {
        //TODO replace with threat intel monitor
        return new Monitor(
                request.getMethod() == RestRequest.Method.POST ? Monitor.NO_ID : request.getId(),
                Monitor.NO_VERSION,
                request.getThreatIntelMonitor().getName(),
                request.getThreatIntelMonitor().isEnabled(),
                request.getThreatIntelMonitor().getSchedule(),
                Instant.now(),
                Instant.now(),
//                "CUSTOM_" +
                Monitor.MonitorType.DOC_LEVEL_MONITOR.getValue(),
                request.getThreatIntelMonitor().getUser(),
                1,
                List.of(new DocLevelMonitorInput("", List.of("*"), Collections.emptyList())),
                Collections.emptyList(),
                Collections.emptyMap(),
                new DataSources(),
                PLUGIN_OWNER_FIELD
        );
    }

    private PerIocTypeScanInput getPerIocTypeScanInput(Monitor monitor) {
        return null;
    }
}
