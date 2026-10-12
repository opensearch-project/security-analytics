/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.TotalHits;
import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.core.action.ActionListener;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.authuser.User;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.Strings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.GetAlertsAction;
import org.opensearch.securityanalytics.action.GetAlertsRequest;
import org.opensearch.securityanalytics.action.GetAlertsResponse;
import org.opensearch.securityanalytics.action.SearchDetectorRequest;
import org.opensearch.securityanalytics.alerts.AlertsService;
import org.opensearch.securityanalytics.alerts.DetectorMonitors;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

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

    /**
     * Maximum number of detectors whose alerts are searched (the default index.max_result_window of the detectors
     * index): the alerts of further detectors are not returned, which is logged at WARN.
     */
    private static final int MAX_DETECTORS = 10000;


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

        boolean noDetectorId = request.getDetectorId() == null || request.getDetectorId().isEmpty();
        if (request.getLogType() == null && noDetectorId) {
            // No detector id or log type: alerts of all detectors visible to the caller, with a single search of the
            // alert indices of their log types. Detector visibility is enforced by TransportSearchDetectorAction
            // (backend role filtering or resource sharing).
            searchDetectors(QueryBuilders.matchAllQuery(), ActionListener.wrap(
                    detectors -> alertsService.getAlertsOfAllDetectors(
                            detectors,
                            request.getTable(),
                            singleValueFilter(request.getSeverityLevel(), request.getSeverityLevels()),
                            singleValueFilter(request.getAlertState(), request.getAlertStates()),
                            request.getSeverityLevels(),
                            request.getAlertStates(),
                            request.getStartTime(),
                            request.getEndTime(),
                            actionListener
                    ),
                    actionListener::onFailure
            ));
        } else if (request.getLogType() == null) {
            alertsService.getAlertsByDetectorId(
                    request.getDetectorId(),
                    request.getTable(),
                    singleValueFilter(request.getSeverityLevel(), request.getSeverityLevels()),
                    singleValueFilter(request.getAlertState(), request.getAlertStates()),
                    request.getSeverityLevels(),
                    request.getAlertStates(),
                    request.getStartTime(),
                    request.getEndTime(),
                    actionListener
            );
        } else {
            searchDetectors(detectorTypeQuery(request.getLogType()), ActionListener.wrap(
                    detectors -> {
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
                        alertsService.getAlertsOfDetectorType(
                                detectors,
                                request.getTable(),
                                singleValueFilter(request.getSeverityLevel(), request.getSeverityLevels()),
                                singleValueFilter(request.getAlertState(), request.getAlertStates()),
                                request.getSeverityLevels(),
                                request.getAlertStates(),
                                request.getStartTime(),
                                request.getEndTime(),
                                actionListener
                        );
                    },
                    actionListener::onFailure
            ));
        }
    }

    /**
     * The single value filter (passed on to Alerting, or applied by the search of the alerts of all detectors): a comma
     * separated multi value severityLevel or alertState is applied as a terms filter on all its values instead (see
     * {@link GetAlertsRequest#getSeverityLevels()} and {@link GetAlertsRequest#getAlertStates()}), with the single value
     * filter left at ALL.
     */
    static String singleValueFilter(String value, List<String> multiValues) {
        return multiValues.isEmpty() ? value : GetAlertsRequest.ALL;
    }

    /**
     * Query for the detectors of a log type. detector_type is matched case-insensitively: a detector can be stored with
     * a mixed-case detector_type (e.g. Windows), while its log type, and the name of its alert indices, is the
     * lowercased value.
     */
    static QueryBuilder detectorTypeQuery(String logType) {
        // "detector" is nested type so we have to use nested query
        return QueryBuilders.nestedQuery(
                "detector",
                QueryBuilders.boolQuery().must(QueryBuilders.termQuery(DETECTOR_TYPE_PATH, logType).caseInsensitive(true)),
                ScoreMode.None
        );
    }

    /**
     * Search request for the detectors matching the query, fetching only the detector fields needed to find their
     * alerts. Detector visibility filtering (backend roles or resource sharing) is applied to it by
     * {@link TransportSearchDetectorAction}.
     */
    static SearchRequest detectorsSearchRequest(QueryBuilder queryBuilder) {
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(queryBuilder);
        searchSourceBuilder.fetchSource(DetectorMonitors.SOURCE_INCLUDES, Strings.EMPTY_ARRAY);
        searchSourceBuilder.size(MAX_DETECTORS);
        SearchRequest searchRequest = new SearchRequest();
        searchRequest.indices(Detector.DETECTORS_INDEX);
        searchRequest.source(searchSourceBuilder);
        searchRequest.preference(Preference.PRIMARY_FIRST.type());
        return searchRequest;
    }

    static List<DetectorMonitors> parseDetectors(SearchResponse searchResponse, NamedXContentRegistry xContentRegistry) throws IOException {
        List<DetectorMonitors> detectors = new ArrayList<>();
        for (SearchHit hit : searchResponse.getHits()) {
            try (XContentParser xcp = XContentType.JSON.xContent().createParser(
                    xContentRegistry, LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString())) {
                detectors.add(DetectorMonitors.parse(xcp, hit.getId()));
            }
        }
        return detectors;
    }

    /**
     * Searches detectors through {@link TransportSearchDetectorAction} so that only detectors visible to the caller
     * are returned.
     */
    private void searchDetectors(QueryBuilder queryBuilder, ActionListener<List<DetectorMonitors>> listener) {
        transportSearchDetectorAction.execute(new SearchDetectorRequest(detectorsSearchRequest(queryBuilder)), new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse searchResponse) {
                List<DetectorMonitors> detectors;
                try {
                    detectors = parseDetectors(searchResponse, xContentRegistry);
                } catch (IOException e) {
                    listener.onFailure(e);
                    return;
                }
                TotalHits totalHits = searchResponse.getHits().getTotalHits();
                if (totalHits != null && totalHits.value() > detectors.size()) {
                    log.warn("Only alerts of the first {} of {} detectors are returned", detectors.size(), totalHits.value());
                }
                listener.onResponse(detectors);
            }

            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        });
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}