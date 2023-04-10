/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.RestStatus;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.GetAlertsAction;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.securityanalytics.action.GetAlertsResponse;
import org.opensearch.securityanalytics.action.SearchDetectorRequest;
import org.opensearch.securityanalytics.alerts.AlertsService;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.DetectorUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import static org.opensearch.securityanalytics.util.DetectorUtils.DETECTOR_TYPE_PATH;

public class TransportGetAlertsAction extends HandledTransportAction<GetAlertsRequest, GetAlertsResponse> implements SecureTransportAction {

    private final TransportSearchDetectorAction transportSearchDetectorAction;

    private final NamedXContentRegistry xContentRegistry;

    private final ClusterService clusterService;

    private final Settings settings;

    private final ThreadPool threadPool;

    private final AlertsService alertsService;

    private volatile Boolean filterByEnabled;

    private static final Logger log = LogManager.getLogger(TransportGetAlertsAction.class);


    @Inject
    public TransportGetAlertsAction(TransportService transportService, ActionFilters actionFilters, ClusterService clusterService, TransportSearchDetectorAction transportSearchDetectorAction, ThreadPool threadPool, Settings settings, NamedXContentRegistry xContentRegistry, Client client) {
        super(GetAlertsAction.NAME, transportService, actionFilters, GetAlertsRequest::new);
        this.transportSearchDetectorAction = transportSearchDetectorAction;
        this.xContentRegistry = xContentRegistry;
        this.alertsService = new AlertsService(client);
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(Task task, GetAlertsRequest request, ActionListener<GetAlertsResponse> actionListener) {

        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }

        if (request.getDetectorType() == null) {
            alertsService.getAlertsByDetectorId(
                    request.getDetectorId(),
                    request.getTable(),
                    request.getSeverityLevel(),
                    request.getAlertState(),
                    actionListener
            );
        } else {
            // "detector" is nested type so we have to use nested query
            NestedQueryBuilder queryBuilder =
                    QueryBuilders.nestedQuery(
                            "detector",
                            QueryBuilders.boolQuery().must(
                                    QueryBuilders.matchQuery(
                                            DETECTOR_TYPE_PATH,
                                            request.getDetectorType().getDetectorType()
                                    )
                            ),
                            ScoreMode.None
                    );
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(queryBuilder);
            searchSourceBuilder.fetchSource(true);
            SearchRequest searchRequest = new SearchRequest();
            searchRequest.indices(Detector.DETECTORS_INDEX);
            searchRequest.source(searchSourceBuilder);

            transportSearchDetectorAction.execute(new SearchDetectorRequest(searchRequest), new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse searchResponse) {
                    try {
                        List<Detector> detectors = DetectorUtils.getDetectors(searchResponse, xContentRegistry);
                        if (detectors.size() == 0) {
                            actionListener.onFailure(
                                SecurityAnalyticsException.wrap(
                                    new OpenSearchStatusException(
                                            "No detectors found for provided type", RestStatus.NOT_FOUND
                                    )
                                )
                            );
                            return;
                        }
                        alertsService.getAlerts(
                                detectors,
                                request.getDetectorType(),
                                request.getTable(),
                                request.getSeverityLevel(),
                                request.getAlertState(),
                                actionListener
                        );
                    } catch (IOException e) {
                        actionListener.onFailure(e);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    actionListener.onFailure(e);
                }
            });

        }
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}