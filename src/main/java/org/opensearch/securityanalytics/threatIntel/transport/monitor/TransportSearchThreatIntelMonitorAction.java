package org.opensearch.securityanalytics.threatIntel.transport.monitor;

import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.SearchMonitorRequest;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.ScheduledJob;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.monitor.SearchThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.SearchThreatIntelMonitorRequest;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelMonitorDto;
import org.opensearch.securityanalytics.threatIntel.util.ThreatIntelMonitorUtils;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import static org.opensearch.securityanalytics.util.DetectorUtils.getEmptySearchResponse;

public class TransportSearchThreatIntelMonitorAction extends HandledTransportAction<SearchThreatIntelMonitorRequest, SearchResponse> implements SecureTransportAction {

    private final NamedXContentRegistry xContentRegistry;
    private final Client client;
    private final ClusterService clusterService;
    private final Settings settings;
    private final ThreadPool threadPool;
    private Boolean filterByEnabled;

    @Inject
    public TransportSearchThreatIntelMonitorAction(TransportService transportService,
                                                   ClusterService clusterService,
                                                   ActionFilters actionFilters,
                                                   NamedXContentRegistry xContentRegistry,
                                                   Settings settings,
                                                   Client client,
                                                   ThreadPool threadPool) {
        super(SearchThreatIntelMonitorAction.NAME, transportService, actionFilters, SearchThreatIntelMonitorRequest::new);
        this.xContentRegistry = xContentRegistry;
        this.client = client;
        this.clusterService = clusterService;
        this.settings = settings;
        this.threadPool = threadPool;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(Task task, SearchThreatIntelMonitorRequest request, ActionListener<SearchResponse> listener) {
        User user = readUserFromThreadContext(this.threadPool);

//        if (doFilterForUser(user, this.filterByEnabled)) {
//            // security is enabled and filterby is enabled
//            log.info("Filtering result by: {}", user.getBackendRoles());
//            addFilter(user, request.searchRequest().source(), "detector.user.backend_roles.keyword");
//        } // TODO

        this.threadPool.getThreadContext().stashContext();

        //TODO change search request to fetch threat intel monitors
        AlertingPluginInterface.INSTANCE.searchMonitors((NodeClient) client, new SearchMonitorRequest(request.searchRequest()), ActionListener.wrap(
                response -> {
                    for (SearchHit hit : response.getHits().getHits()) {
                        XContentParser parser = XContentType.JSON.xContent()
                                .createParser(xContentRegistry, LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString());
                        ScheduledJob monitor = ScheduledJob.Companion.parse(parser, hit.getId(), hit.getVersion());
                        ThreatIntelMonitorDto threatIntelMonitorDto = ThreatIntelMonitorUtils.buildThreatIntelMonitorDto(hit.getId(), (Monitor) monitor, xContentRegistry);
                        XContentBuilder builder = threatIntelMonitorDto.toXContent(XContentBuilder.builder(XContentType.JSON.xContent()), null);
                        hit.sourceRef(BytesReference.bytes(builder));
                    }
                    listener.onResponse(response);
                },
                e -> {
                    if (e instanceof IndexNotFoundException) {
                        listener.onResponse(getEmptySearchResponse());
                        return;
                    }
                    log.error("Failed to search threat intel monitors", e);
                    listener.onFailure(e);
                }
        ));
    }


    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}
