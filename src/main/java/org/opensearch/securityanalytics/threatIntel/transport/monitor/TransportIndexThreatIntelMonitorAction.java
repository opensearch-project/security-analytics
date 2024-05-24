package org.opensearch.securityanalytics.threatIntel.transport.monitor;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
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
import org.opensearch.commons.alerting.action.IndexMonitorResponse;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.DocLevelMonitorInput;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteDocLevelMonitorInput;
import org.opensearch.commons.alerting.model.remote.monitors.RemoteMonitorTrigger;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.monitor.IndexThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.IndexThreatIntelMonitorRequest;
import org.opensearch.securityanalytics.threatIntel.action.monitor.response.IndexThreatIntelMonitorResponse;
import org.opensearch.securityanalytics.threatIntel.model.monitor.PerIocTypeScanInput;
import org.opensearch.securityanalytics.threatIntel.model.monitor.ThreatIntelInput;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelTriggerDto;
import org.opensearch.securityanalytics.threatIntel.util.ThreatIntelMonitorUtils;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.threatIntel.model.monitor.ThreatIntelMonitorRunner.THREAT_INTEL_MONITOR_TYPE;
import static org.opensearch.securityanalytics.transport.TransportIndexDetectorAction.PLUGIN_OWNER_FIELD;

public class TransportIndexThreatIntelMonitorAction extends HandledTransportAction<IndexThreatIntelMonitorRequest, IndexThreatIntelMonitorResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(TransportIndexThreatIntelMonitorAction.class);

    private final ThreadPool threadPool;
    private final Settings settings;
    private final NamedWriteableRegistry namedWriteableRegistry;
    private final NamedXContentRegistry xContentRegistry;
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
            final NamedWriteableRegistry namedWriteableRegistry,
            final NamedXContentRegistry namedXContentRegistry
    ) {
        super(IndexThreatIntelMonitorAction.NAME, transportService, actionFilters, IndexThreatIntelMonitorRequest::new);
        this.threadPool = threadPool;
        this.settings = settings;
        this.namedWriteableRegistry = namedWriteableRegistry;
        this.xContentRegistry = namedXContentRegistry;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, IndexThreatIntelMonitorRequest request, ActionListener<IndexThreatIntelMonitorResponse> listener) {
        try {
            // validate user
            User user = readUserFromThreadContext(this.threadPool);
            String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
            if (!"".equals(validateBackendRoleMessage)) {
                listener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException(validateBackendRoleMessage, RestStatus.FORBIDDEN)));
                return;
            }

            IndexMonitorRequest indexMonitorRequest = buildIndexMonitorRequest(request);
            AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, indexMonitorRequest, namedWriteableRegistry, ActionListener.wrap(
                    r -> {
                        log.debug(
                                "{} threat intel monitor {}", request.getMethod() == RestRequest.Method.PUT ? "Updated" : "Created",
                                r.getId()
                        );
                        IndexThreatIntelMonitorResponse response = getIndexThreatIntelMonitorResponse(r, user);
                        listener.onResponse(response);
                    }, e -> {
                        log.error("failed to creat threat intel monitor", e);
                        listener.onFailure(new SecurityAnalyticsException("Failed to create threat intel monitor", RestStatus.INTERNAL_SERVER_ERROR, e));
                    }
            ));
        } catch (Exception e) {
            log.error(() -> new ParameterizedMessage("Unexpected failure while indexing threat intel monitor {} named {}", request.getId(), request.getMonitor().getName()));
            listener.onFailure(new SecurityAnalyticsException("Unexpected failure while indexing threat intel monitor", RestStatus.INTERNAL_SERVER_ERROR, e));
        }
    }

    private IndexThreatIntelMonitorResponse getIndexThreatIntelMonitorResponse(IndexMonitorResponse r, User user) throws IOException {
        IndexThreatIntelMonitorResponse response = new IndexThreatIntelMonitorResponse(r.getId(), r.getVersion(), r.getSeqNo(), r.getPrimaryTerm(),
                ThreatIntelMonitorUtils.buildThreatIntelMonitorDto(r.getId(), r.getMonitor(), xContentRegistry));
        return response;
    }

    private IndexMonitorRequest buildIndexMonitorRequest(IndexThreatIntelMonitorRequest request) throws IOException {
        String id = request.getMethod() == RestRequest.Method.POST ? Monitor.NO_ID : request.getId();
        return new IndexMonitorRequest(
                id,
                SequenceNumbers.UNASSIGNED_SEQ_NO,
                SequenceNumbers.UNASSIGNED_PRIMARY_TERM,
                WriteRequest.RefreshPolicy.IMMEDIATE,
                request.getMethod(),
                buildThreatIntelMonitor(request),
                null
        );
    }

    private Monitor buildThreatIntelMonitor(IndexThreatIntelMonitorRequest request) throws IOException {
        //TODO replace with threat intel monitor
        DocLevelMonitorInput docLevelMonitorInput = new DocLevelMonitorInput(
                String.format("threat intel input for monitor named %s", request.getMonitor().getName()),
                request.getMonitor().getIndices(),
                Collections.emptyList() // no percolate queries
        );
        List<PerIocTypeScanInput> perIocTypeScanInputs = request.getMonitor().getPerIocTypeScanInputList().stream().map(
                it -> new PerIocTypeScanInput(it.getIocType(), it.getIndexToFieldsMap())
        ).collect(Collectors.toList());
        ThreatIntelInput threatIntelInput = new ThreatIntelInput(perIocTypeScanInputs);
        RemoteDocLevelMonitorInput remoteDocLevelMonitorInput = new RemoteDocLevelMonitorInput(
                threatIntelInput.getThreatIntelInputAsBytesReference(),
                docLevelMonitorInput);
        List<RemoteMonitorTrigger> triggers = new ArrayList<>();
        for (ThreatIntelTriggerDto it : request.getMonitor().getTriggers()) {
            try {
                RemoteMonitorTrigger trigger = ThreatIntelMonitorUtils.buildRemoteMonitorTrigger(it);
                triggers.add(trigger);
            } catch (IOException e) {
                logger.error(() -> new ParameterizedMessage("failed to parse threat intel trigger {}", it.getId()), e);
                throw new RuntimeException(e);
            }
        }
        return new Monitor(
                request.getMethod() == RestRequest.Method.POST ? Monitor.NO_ID : request.getId(),
                Monitor.NO_VERSION,
                StringUtils.isBlank(request.getMonitor().getName()) ? "threat_intel_monitor" : request.getMonitor().getName(),
                request.getMonitor().isEnabled(),
                request.getMonitor().getSchedule(),
                Instant.now(),
                request.getMonitor().isEnabled() ? Instant.now() : null,
                THREAT_INTEL_MONITOR_TYPE,
                request.getMonitor().getUser(),
                1,
                List.of(remoteDocLevelMonitorInput),
                triggers,
                Collections.emptyMap(),
                new DataSources(),
                PLUGIN_OWNER_FIELD
        );
    }


}
