package org.opensearch.securityanalytics.threatIntel.transport.monitor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.model.Alert;
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
import org.opensearch.securityanalytics.model.threatintel.ThreatIntelAlert;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.monitor.UpdateThreatIntelAlertStatusAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.SearchThreatIntelMonitorRequest;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.UpdateThreatIntelAlertStatusRequest;
import org.opensearch.securityanalytics.threatIntel.action.monitor.response.UpdateThreatIntelAlertsStatusResponse;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.ThreatIntelAlertService;
import org.opensearch.securityanalytics.threatIntel.iocscan.service.ThreatIntelMonitorRunner;
import org.opensearch.securityanalytics.threatIntel.sacommons.monitor.ThreatIntelAlertDto;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static org.opensearch.securityanalytics.transport.TransportIndexDetectorAction.PLUGIN_OWNER_FIELD;

public class TransportUpdateThreatIntelAlertStatusAction extends HandledTransportAction<UpdateThreatIntelAlertStatusRequest, UpdateThreatIntelAlertsStatusResponse> implements SecureTransportAction {
    private final Client client;
    private final TransportSearchThreatIntelMonitorAction transportSearchThreatIntelMonitorAction;

    private final NamedXContentRegistry xContentRegistry;

    private final ClusterService clusterService;

    private final Settings settings;

    private final ThreadPool threadPool;

    private final ThreatIntelAlertService alertsService;

    private volatile Boolean filterByEnabled;

    private static final Logger log = LogManager.getLogger(TransportUpdateThreatIntelAlertStatusAction.class);


    @Inject
    public TransportUpdateThreatIntelAlertStatusAction(TransportService transportService,
                                                       ActionFilters actionFilters,
                                                       ClusterService clusterService,
                                                       ThreadPool threadPool,
                                                       Settings settings,
                                                       NamedXContentRegistry xContentRegistry,
                                                       Client client,
                                                       TransportSearchThreatIntelMonitorAction transportSearchThreatIntelMonitorAction1, ThreatIntelAlertService alertsService) {
        super(UpdateThreatIntelAlertStatusAction.NAME, transportService, actionFilters, UpdateThreatIntelAlertStatusRequest::new);
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

    @Override
    protected void doExecute(Task task, UpdateThreatIntelAlertStatusRequest request, ActionListener<UpdateThreatIntelAlertsStatusResponse> listener) {
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
                        log.error("Threat intel monitor not found. No alerts to update");
                        listener.onFailure(new SecurityAnalyticsException("Threat intel monitor not found. No alerts to update",
                                RestStatus.BAD_REQUEST,
                                new IllegalArgumentException("Threat intel monitor not found. No alerts to update")));
                    }
                    onSearchMonitorResponse(monitorIds, request, listener);
                },

                e -> {
                    if (e instanceof IndexNotFoundException) {
                        log.error("Threat intel monitor not found. No alerts to update");
                        listener.onFailure(new SecurityAnalyticsException("Threat intel monitor not found. No alerts to update",
                                RestStatus.BAD_REQUEST,
                                new IllegalArgumentException("Threat intel monitor not found. No alerts to update")));
                        return;
                    }
                    log.error("Failed to update threat intel monitor alerts status", e);
                    listener.onFailure(e);
                }
        ));

    }

    private void onSearchMonitorResponse(List<String> monitorIds,
                                         UpdateThreatIntelAlertStatusRequest request,
                                         ActionListener<UpdateThreatIntelAlertsStatusResponse> listener) {
        SearchSourceBuilder searchSourceBuilder = getSearchSourceQueryingForAlertsToUpdate(monitorIds, request, listener);
        alertsService.search(searchSourceBuilder, ActionListener.wrap(
                searchResponse -> {
                    List<ThreatIntelAlert> alerts = new ArrayList<>();
                    if (searchResponse.getHits() == null || searchResponse.getHits().getHits() == null || searchResponse.getHits().getHits().length == 0) {
                        log.error("No alerts found to update");
                        listener.onFailure(new SecurityAnalyticsException("No alerts found to update",
                                RestStatus.BAD_REQUEST,
                                new ResourceNotFoundException("No alerts found to update")));
                        return;
                    }
                    for (SearchHit hit : searchResponse.getHits().getHits()) {
                        XContentParser xcp = XContentType.JSON.xContent().createParser(
                                xContentRegistry,
                                LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                        );
                        if (xcp.currentToken() == null)
                            xcp.nextToken();
                        ThreatIntelAlert alert = ThreatIntelAlert.parse(
                                xcp,
                                hit.getVersion(),
                                hit.getSeqNo(),
                                hit.getPrimaryTerm()
                        );
                        alerts.add(alert);
                    }
                    updateAlerts(monitorIds, alerts, request.getState(), listener);
                }, e -> {
                    log.error("Failed to search for threat intel alerts", e);
                    listener.onFailure(e);
                }
        ));
    }

    private static SearchSourceBuilder getSearchSourceQueryingForAlertsToUpdate(List<String> monitorIds, UpdateThreatIntelAlertStatusRequest request, ActionListener<UpdateThreatIntelAlertsStatusResponse> listener) {
        BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery();
        BoolQueryBuilder monitorIdMatchQuery = QueryBuilders.boolQuery();
        for (String monitorId : monitorIds) {
            monitorIdMatchQuery.should(QueryBuilders.matchQuery(ThreatIntelAlert.MONITOR_ID_FIELD, monitorId));

        }
        queryBuilder.filter(monitorIdMatchQuery);

        BoolQueryBuilder idMatchQuery = QueryBuilders.boolQuery();
        for (String id : request.getAlertIds()) {
            idMatchQuery.should(QueryBuilders.matchQuery("_id", id));

        }
        queryBuilder.filter(idMatchQuery);

        if (request.getState() == Alert.State.COMPLETED) {
            queryBuilder.filter(QueryBuilders.matchQuery(ThreatIntelAlert.STATE_FIELD, Alert.State.ACKNOWLEDGED.toString()));
        } else if (request.getState() == Alert.State.ACKNOWLEDGED) {
            queryBuilder.filter(QueryBuilders.matchQuery(ThreatIntelAlert.STATE_FIELD, Alert.State.ACTIVE.toString()));
        } else {
            log.error("Threat intel monitor not found. No alerts to update");
            listener.onFailure(new SecurityAnalyticsException("Threat intel monitor not found. No alerts to update",
                    RestStatus.BAD_REQUEST,
                    new IllegalArgumentException("Threat intel monitor not found. No alerts to update")));
            return null;
        }


        return new SearchSourceBuilder()
                .version(true)
                .seqNoAndPrimaryTerm(true)
                .query(queryBuilder)
                .size(request.getAlertIds().size());
    }

    private void updateAlerts(List<String> monitorIds, List<ThreatIntelAlert> alerts, Alert.State state, ActionListener<UpdateThreatIntelAlertsStatusResponse> listener) {
        List<String> failedAlerts = new ArrayList<>();
        List<ThreatIntelAlert> alertsToUpdate = new ArrayList<>();
        for (ThreatIntelAlert alert : alerts) {
            if (isValidStateTransitionRequested(alert.getState(), state)) {
                ThreatIntelAlert updatedAlertModel = ThreatIntelAlert.updateStatus(alert, state);
                alertsToUpdate.add(updatedAlertModel);
            } else {
                log.error("Alert {} : updating alert state from {} to {} is not allowed!", alert.getId(), alert.getState(), state);
                failedAlerts.add(alert.getId());
            }
        }
        alertsService.bulkIndexEntities(emptyList(), alertsToUpdate, ActionListener.wrap(
                r -> { // todo change response to return failure messaages
                    List<ThreatIntelAlertDto> updatedAlerts = new ArrayList<>();
                    SearchSourceBuilder searchSourceQueryingForAlerts = getSearchSourceQueryingForUpdatedAlerts(
                            monitorIds,
                            alertsToUpdate.stream().map(ThreatIntelAlert::getId).collect(Collectors.toList()));
                    alertsService.search(searchSourceQueryingForAlerts, ActionListener.wrap(
                            searchResponse -> {
                                if (
                                        searchResponse.getHits() == null ||
                                                searchResponse.getHits().getHits() == null ||
                                                searchResponse.getHits().getHits().length == 0
                                ) {
                                    log.error("No alerts found to update");
                                    listener.onFailure(new SecurityAnalyticsException("No alerts found to update",
                                            RestStatus.BAD_REQUEST,
                                            new ResourceNotFoundException("No alerts found to update")));
                                    return;
                                }
                                for (SearchHit hit : searchResponse.getHits().getHits()) {
                                    XContentParser xcp = XContentType.JSON.xContent().createParser(
                                            xContentRegistry,
                                            LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                                    );
                                    if (xcp.currentToken() == null)
                                        xcp.nextToken();
                                    if (xcp.currentToken() == null)
                                        xcp.nextToken();
                                    ThreatIntelAlert alert = ThreatIntelAlert.parse(xcp, hit.getVersion());
                                    updatedAlerts.add(new ThreatIntelAlertDto(alert, hit.getSeqNo(), hit.getPrimaryTerm()));
                                }
                                listener.onResponse(new UpdateThreatIntelAlertsStatusResponse(
                                        updatedAlerts,
                                        failedAlerts
                                ));
                            },
                            e -> {
                                log.error("Failed to fetch the updated alerts to return. Returning empty list for updated alerts although some might have been updated", e);
                                listener.onResponse(new UpdateThreatIntelAlertsStatusResponse(
                                        emptyList(),
                                        failedAlerts
                                ));
                            }
                    ));

                }, e -> {
                    log.error("Failed to bulk update status of threat intel alerts to " + state, e);
                    listener.onFailure(e);
                }
        ));
    }

    private static SearchSourceBuilder getSearchSourceQueryingForUpdatedAlerts(List<String> monitorIds, List<String> alertIds) {
        BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery();
        BoolQueryBuilder monitorIdMatchQuery = QueryBuilders.boolQuery();
        for (String monitorId : monitorIds) {
            monitorIdMatchQuery.should(QueryBuilders.matchQuery(ThreatIntelAlert.MONITOR_ID_FIELD, monitorId));

        }
        queryBuilder.filter(monitorIdMatchQuery);

        BoolQueryBuilder idMatchQuery = QueryBuilders.boolQuery();
        for (String id : alertIds) {
            idMatchQuery.should(QueryBuilders.matchQuery("_id", id));

        }
        queryBuilder.filter(idMatchQuery);

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                .version(true)
                .seqNoAndPrimaryTerm(true)
                .query(queryBuilder)
                .size(alertIds.size());
        return searchSourceBuilder;
    }

    private boolean isValidStateTransitionRequested(Alert.State currState, Alert.State nextState) {
        if (currState.equals(Alert.State.ACKNOWLEDGED) && nextState.equals(Alert.State.COMPLETED)) {
            return true;
        } else if (currState.equals(Alert.State.ACTIVE) && nextState.equals(Alert.State.ACKNOWLEDGED)) {
            return true;
        }
        return false;
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}
