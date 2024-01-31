/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.io.IOException;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.core.action.ActionListener;
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
import org.opensearch.index.query.MatchAllQueryBuilder;
import org.opensearch.index.query.NestedQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.GetFindingsAction;
import org.opensearch.securityanalytics.action.GetFindingsRequest;
import org.opensearch.securityanalytics.action.GetFindingsResponse;
import org.opensearch.securityanalytics.action.SearchDetectorRequest;
import org.opensearch.securityanalytics.findings.FindingsService;
import org.opensearch.securityanalytics.logtype.LogTypeService;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.DetectorUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;


import static org.opensearch.securityanalytics.util.DetectorUtils.DETECTOR_TYPE_PATH;
import static org.opensearch.securityanalytics.util.DetectorUtils.NO_DETECTORS_FOUND;
import static org.opensearch.securityanalytics.util.DetectorUtils.NO_DETECTORS_FOUND_FOR_PROVIDED_TYPE;

public class TransportGetFindingsAction extends HandledTransportAction<GetFindingsRequest, GetFindingsResponse> implements SecureTransportAction {

    private final TransportSearchDetectorAction transportSearchDetectorAction;

    private final NamedXContentRegistry xContentRegistry;

    private final FindingsService findingsService;

    private final DetectorIndices detectorIndices;

    private final ClusterService clusterService;

    private final Settings settings;

    private final ThreadPool threadPool;

    private final LogTypeService logTypeService;

    private volatile Boolean filterByEnabled;

    private static final Logger log = LogManager.getLogger(TransportGetFindingsAction.class);


    @Inject
    public TransportGetFindingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            ClusterService clusterService,
            DetectorIndices detectorIndices,
            Settings settings,
            TransportSearchDetectorAction transportSearchDetectorAction,
            NamedXContentRegistry xContentRegistry,
            Client client,
            LogTypeService logTypeService
    ) {
        super(GetFindingsAction.NAME, transportService, actionFilters, GetFindingsRequest::new);
        this.xContentRegistry = xContentRegistry;
        this.transportSearchDetectorAction = transportSearchDetectorAction;
        this.detectorIndices = detectorIndices;
        this.clusterService = clusterService;
        this.logTypeService = logTypeService;
        this.threadPool = detectorIndices.getThreadPool();
        this.settings = settings;
        this.findingsService = new FindingsService(client);
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(Task task, GetFindingsRequest request, ActionListener<GetFindingsResponse> actionListener) {

        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }

        if (request.getLogType() == null && request.getDetectorId() == null) {
            // Get all the Findings
            SearchRequest searchRequest = getSearchDetectorsRequest(request);
            getFindingsFromDetectors(request, actionListener, searchRequest);

        } else if (request.getLogType() == null) {
            // Get the Findings by DetectorId
            findingsService.getFindingsByDetectorId(
                    request.getDetectorId(),
                    request.getTable(),
                    actionListener
                    );
        } else {
            // Get the Findings when logType is not null
            SearchRequest searchRequest = getSearchDetectorsRequest(request);
            getFindingsFromDetectors(request, actionListener, searchRequest);
        }
    }

    private void getFindingsFromDetectors(GetFindingsRequest findingsRequest, ActionListener<GetFindingsResponse> findingsResponseActionListener, SearchRequest searchRequest) {
        transportSearchDetectorAction.execute(new SearchDetectorRequest(searchRequest), new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse searchResponse) {
                try {
                    List<Detector> detectors = DetectorUtils.getDetectors(searchResponse, xContentRegistry);
                    if (detectors.size() == 0) {
                        findingsResponseActionListener.onFailure(
                                SecurityAnalyticsException.wrap(
                                        new OpenSearchStatusException(
                                                findingsRequest.getLogType() == null ? NO_DETECTORS_FOUND : NO_DETECTORS_FOUND_FOR_PROVIDED_TYPE, RestStatus.NOT_FOUND
                                        )
                                )
                        );
                        return;
                    }
                    findingsService.getFindings(
                            detectors,
                            findingsRequest.getLogType() == null ? "*" : findingsRequest.getLogType(),
                            findingsRequest.getTable(),
                            findingsRequest.getSeverity(),
                            findingsResponseActionListener
                    );
                } catch (IOException e) {
                    findingsResponseActionListener.onFailure(e);
                }
            }
            @Override
            public void onFailure(Exception e) {
                findingsResponseActionListener.onFailure(e);
            }
        });
    }

    private static SearchRequest getSearchDetectorsRequest(GetFindingsRequest findingsRequest) {
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        if (findingsRequest.getLogType() != null) {
            NestedQueryBuilder queryBuilder = QueryBuilders.nestedQuery(
                    "detector",
                    QueryBuilders.boolQuery().must(
                            QueryBuilders.matchQuery(
                                    DETECTOR_TYPE_PATH,
                                    findingsRequest.getLogType()
                            )
                    ),
                    ScoreMode.None
            );
            searchSourceBuilder.query(queryBuilder);
        }
        else {
            MatchAllQueryBuilder queryBuilder = QueryBuilders.matchAllQuery();
            searchSourceBuilder.query(queryBuilder);
        }
        searchSourceBuilder.fetchSource(true);
        SearchRequest searchRequest = new SearchRequest();
        searchRequest.indices(Detector.DETECTORS_INDEX);
        searchRequest.source(searchSourceBuilder);
        searchRequest.preference(Preference.PRIMARY_FIRST.type());
        return searchRequest;
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }

}