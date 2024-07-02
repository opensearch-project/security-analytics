package org.opensearch.securityanalytics.threatIntel.transport.monitor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.Table;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.FieldSortBuilder;
import org.opensearch.search.sort.SortBuilders;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.monitor.GetThreatIntelAlertsAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.GetThreatIntelAlertsRequest;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.SearchThreatIntelMonitorRequest;
import org.opensearch.securityanalytics.threatIntel.action.monitor.response.GetThreatIntelAlertsResponse;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.ThreatIntelAlertService;
import org.opensearch.securityanalytics.threatIntel.iocscan.service.ThreatIntelMonitorRunner;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelAlertDto;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.transport.TransportIndexDetectorAction.PLUGIN_OWNER_FIELD;

public class TransportGetThreatIntelAlertsAction extends HandledTransportAction<GetThreatIntelAlertsRequest, GetThreatIntelAlertsResponse> implements SecureTransportAction {

    private final Client client;
    private final TransportSearchThreatIntelMonitorAction transportSearchThreatIntelMonitorAction;

    private final NamedXContentRegistry xContentRegistry;

    private final ClusterService clusterService;

    private final Settings settings;

    private final ThreadPool threadPool;

    private final ThreatIntelAlertService alertsService;

    private volatile Boolean filterByEnabled;

    private static final Logger log = LogManager.getLogger(TransportGetThreatIntelAlertsAction.class);


    @Inject
    public TransportGetThreatIntelAlertsAction(TransportService transportService,
                                               ActionFilters actionFilters,
                                               ClusterService clusterService,
                                               ThreadPool threadPool,
                                               Settings settings,
                                               NamedXContentRegistry xContentRegistry,
                                               Client client,
                                               TransportSearchThreatIntelMonitorAction transportSearchThreatIntelMonitorAction1, ThreatIntelAlertService alertsService) {
        super(GetThreatIntelAlertsAction.NAME, transportService, actionFilters, GetThreatIntelAlertsRequest::new);
        this.client = client;
        this.transportSearchThreatIntelMonitorAction = transportSearchThreatIntelMonitorAction1;
        this.xContentRegistry = xContentRegistry;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.alertsService = alertsService;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }

    @Override
    protected void doExecute(Task task, GetThreatIntelAlertsRequest request, ActionListener<GetThreatIntelAlertsResponse> listener) {
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }
        //fetch monitors and search
        SearchRequest threatIntelMonitorsSearchRequest = new SearchRequest();
        threatIntelMonitorsSearchRequest.indices(".opendistro-alerting-config");
        BoolQueryBuilder boolQueryBuilder = QueryBuilders.boolQuery();
        boolQueryBuilder.should().add(new BoolQueryBuilder().must(QueryBuilders.matchQuery("monitor.owner", PLUGIN_OWNER_FIELD)));
        boolQueryBuilder.should().add(new BoolQueryBuilder().must(QueryBuilders.matchQuery("monitor.monitor_type", ThreatIntelMonitorRunner.THREAT_INTEL_MONITOR_TYPE)));
        threatIntelMonitorsSearchRequest.source(new SearchSourceBuilder().query(boolQueryBuilder));
        transportSearchThreatIntelMonitorAction.execute(new SearchThreatIntelMonitorRequest(threatIntelMonitorsSearchRequest), ActionListener.wrap(
                searchResponse -> {
                    List<String> monitorIds = searchResponse.getHits() == null || searchResponse.getHits().getHits() == null ? new ArrayList<>() :
                            Arrays.stream(searchResponse.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toList());
                    if (monitorIds.isEmpty()) {
                        listener.onResponse(new GetThreatIntelAlertsResponse(Collections.emptyList(), 0));
                        return;
                    }
                    getAlerts(monitorIds, request, listener);
                },

                e -> {
                    if (e instanceof IndexNotFoundException) {
                        log.debug("Monitor index not created. Returning 0 threat intel alerts");
                        listener.onResponse(new GetThreatIntelAlertsResponse(Collections.emptyList(), 0));
                        return;
                    }
                    log.error("Failed to get threat intel monitor alerts", e);
                    listener.onFailure(e);
                }
        ));
    }

    private void getAlerts(List<String> monitorIds,
                           GetThreatIntelAlertsRequest request,
                           ActionListener<GetThreatIntelAlertsResponse> listener) {
        BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery();
        BoolQueryBuilder monitorIdMatchQuery = QueryBuilders.boolQuery();
        for (String monitorId : monitorIds) {
            monitorIdMatchQuery.should(QueryBuilders.boolQuery()
                    .must(QueryBuilders.matchQuery("monitor_id", monitorId)));

        }
        queryBuilder.filter(monitorIdMatchQuery);
        Table tableProp = request.getTable();
        FieldSortBuilder sortBuilder = SortBuilders
                .fieldSort(tableProp.getSortString())
                .order(SortOrder.fromString(tableProp.getSortOrder()));
        if (tableProp.getMissing() != null && !tableProp.getMissing().isEmpty()) {
            sortBuilder.missing(tableProp.getMissing());
        }

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                .version(true)
                .seqNoAndPrimaryTerm(true)
                .query(queryBuilder)
                .sort(sortBuilder)
                .size(tableProp.getSize())
                .from(tableProp.getStartIndex());
        alertsService.search(searchSourceBuilder, ActionListener.wrap(
                searchResponse -> {
                    List<ThreatIntelAlertDto> alerts = new ArrayList<>();
                    if (searchResponse.getHits() == null || searchResponse.getHits().getHits() == null || searchResponse.getHits().getHits().length == 0) {
                        listener.onResponse(new GetThreatIntelAlertsResponse(Collections.emptyList(), 0));
                        return;
                    }
                    for (SearchHit hit : searchResponse.getHits().getHits()) {
                        XContentParser xcp = XContentType.JSON.xContent().createParser(
                                xContentRegistry,
                                LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                        );
                        if (xcp.currentToken() == null)
                            xcp.nextToken();
                        ThreatIntelAlert alert = ThreatIntelAlert.parse(xcp, hit.getVersion());
                        alerts.add(new ThreatIntelAlertDto(alert, hit.getSeqNo(), hit.getPrimaryTerm()));
                    }
                    listener.onResponse(new GetThreatIntelAlertsResponse(alerts, (int) searchResponse.getHits().getTotalHits().value));
                }, e -> {
                    log.error("Failed to search for threat intel alerts", e);
                    listener.onFailure(e);
                }
        ));
    }
}