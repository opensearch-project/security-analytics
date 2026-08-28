/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.StepListener;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.search.aggregations.Aggregations;
import org.opensearch.search.aggregations.bucket.terms.Terms;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.FieldSortBuilder;
import org.opensearch.search.sort.SortBuilder;
import org.opensearch.search.sort.SortBuilders;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.securityanalytics.threatIntel.action.ListIOCsAction;
import org.opensearch.securityanalytics.threatIntel.action.ListIOCsActionRequest;
import org.opensearch.securityanalytics.threatIntel.action.ListIOCsActionResponse;
import org.opensearch.securityanalytics.model.DetailedSTIX2IOCDto;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.model.STIX2IOCDto;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.IocFindingService;
import org.opensearch.securityanalytics.threatIntel.model.DefaultIocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.service.DefaultTifSourceConfigLoaderService;
import org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigService;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.opensearch.securityanalytics.threatIntel.common.TIFJobState.AVAILABLE;
import static org.opensearch.securityanalytics.threatIntel.common.TIFJobState.REFRESHING;
import static org.opensearch.securityanalytics.threatIntel.service.SATIFSourceConfigService.getStateFieldName;

public class TransportListIOCsAction extends HandledTransportAction<ListIOCsActionRequest, ListIOCsActionResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(TransportListIOCsAction.class);

    private final ClusterService clusterService;
    private final TransportSearchTIFSourceConfigsAction transportSearchTIFSourceConfigsAction;
    private final DefaultTifSourceConfigLoaderService defaultTifSourceConfigLoaderService;
    private final Client client;
    private final NamedXContentRegistry xContentRegistry;
    private final ThreadPool threadPool;
    private final SATIFSourceConfigService saTifSourceConfigService;
    private final Settings settings;
    private volatile Boolean filterByEnabled;
    private final IocFindingService iocFindingService;

    public static String IOC_COUNT_AGG_NAME = "ioc_id_count";
    public static String IOC_ID_KEYWORD_FIELD = "ioc_feed_ids.ioc_id.keyword";

    @Inject
    public TransportListIOCsAction(
            final ClusterService clusterService,
            TransportService transportService,
            TransportSearchTIFSourceConfigsAction transportSearchTIFSourceConfigsAction,
            SATIFSourceConfigService saTifSourceConfigService,
            DefaultTifSourceConfigLoaderService defaultTifSourceConfigLoaderService,
            Client client,
            NamedXContentRegistry xContentRegistry,
            ActionFilters actionFilters,
            Settings settings
    ) {
        super(ListIOCsAction.NAME, transportService, actionFilters, ListIOCsActionRequest::new);
        this.clusterService = clusterService;
        this.transportSearchTIFSourceConfigsAction = transportSearchTIFSourceConfigsAction;
        this.saTifSourceConfigService = saTifSourceConfigService;
        this.defaultTifSourceConfigLoaderService = defaultTifSourceConfigLoaderService;
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.threadPool = this.client.threadPool();
        this.settings = settings;
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.iocFindingService = new IocFindingService(client, clusterService, xContentRegistry);
    }

    @Override
    protected void doExecute(Task task, ListIOCsActionRequest request, ActionListener<ListIOCsActionResponse> listener) {
        AsyncListIOCsAction asyncAction = new AsyncListIOCsAction(task, request, listener);
        asyncAction.start();
    }

    class AsyncListIOCsAction {
        private ListIOCsActionRequest request;
        private ActionListener<ListIOCsActionResponse> listener;

        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;

        AsyncListIOCsAction(Task task, ListIOCsActionRequest request, ActionListener<ListIOCsActionResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;
            this.response = new AtomicReference<>();
        }

        void start() {
            // validate user
            User user = readUserFromThreadContext(TransportListIOCsAction.this.threadPool);
            String validateBackendRoleMessage = validateUserBackendRoles(user, TransportListIOCsAction.this.filterByEnabled);
            if (!"".equals(validateBackendRoleMessage)) {
                listener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
                return;
            }
            TransportListIOCsAction.this.threadPool.getThreadContext().stashContext(); // stash context to make calls as admin client

            StepListener<Void> defaultTifConfigsLoadedListener = null;
            try {
                defaultTifConfigsLoadedListener = new StepListener<>();
                defaultTifSourceConfigLoaderService.createDefaultTifConfigsIfNotExists(defaultTifConfigsLoadedListener);
                defaultTifConfigsLoadedListener.whenComplete(r -> searchIocs(), e -> searchIocs());
            } catch (Exception e) {
                log.error("Failed to load default tif source configs. Moving on to list iocs", e);
                searchIocs();
            }
        }

        private void searchIocs() {
            /** get all match threat intel source configs. fetch write index of each config if no iocs provided else fetch just index alias */
            List<String> configIds = request.getFeedIds() == null ? Collections.emptyList() : request.getFeedIds();
            saTifSourceConfigService.searchTIFSourceConfigs(getFeedsSearchSourceBuilder(configIds),
                    ActionListener.wrap(
                            searchResponse -> {
                                List<String> iocIndices = new ArrayList<>();
                                for (SearchHit hit : searchResponse.getHits().getHits()) {
                                    XContentParser xcp = XContentType.JSON.xContent().createParser(
                                            xContentRegistry,
                                            LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                                    );
                                    SATIFSourceConfig config = SATIFSourceConfig.docParse(xcp, hit.getId(), hit.getVersion());
                                    if (config.getIocStoreConfig() instanceof DefaultIocStoreConfig) {
                                        DefaultIocStoreConfig iocStoreConfig = (DefaultIocStoreConfig) config.getIocStoreConfig();
                                        for (DefaultIocStoreConfig.IocToIndexDetails iocToindexDetails : iocStoreConfig.getIocToIndexDetails()) {
                                            String writeIndex = iocToindexDetails.getActiveIndex();
                                            if (writeIndex != null) {
                                                iocIndices.add(writeIndex);
                                            }
                                        }
                                    }
                                }
                                if (iocIndices.isEmpty()) {
                                    log.info("No ioc indices found to query for given threat intel source filtering criteria {}", String.join(",", configIds));
                                    listener.onResponse(new ListIOCsActionResponse(0L, Collections.emptyList()));
                                    return;
                                }
                                listIocs(iocIndices);
                            }, e -> {
                                log.error(String.format("Failed to fetch threat intel source configs. Unable to return Iocs"), e);
                                listener.onFailure(e);
                            }
                    ));
        }

        private void listIocs(List<String> iocIndices) {
            BoolQueryBuilder boolQueryBuilder = QueryBuilders.boolQuery();

            QueryBuilder typeQueryBuilder = QueryBuilders.boolQuery();

            // If any of the 'type' options are 'ALL', do not apply 'type' filter
            if (request.getTypes() != null && request.getTypes().stream().noneMatch(type -> ListIOCsActionRequest.ALL_TYPES_FILTER.equalsIgnoreCase(type))) {
                for (String type : request.getTypes()) {
                    boolQueryBuilder.should(QueryBuilders.matchQuery(STIX2IOC.TYPE_FIELD, type));
                }
                boolQueryBuilder.must(typeQueryBuilder);
            }

            if (request.getTable().getSearchString() != null && !request.getTable().getSearchString().isEmpty()) {
                boolQueryBuilder.must(QueryBuilders.queryStringQuery(request.getTable().getSearchString()));
            }


            SortBuilder<FieldSortBuilder> sortBuilder = SortBuilders
                    .fieldSort(request.getTable().getSortString())
                    .order(SortOrder.fromString(request.getTable().getSortOrder()));

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                    .version(true)
                    .seqNoAndPrimaryTerm(true)
                    .fetchSource(true)
                    .trackTotalHits(true)
                    .query(boolQueryBuilder)
                    .sort(sortBuilder)
                    .size(request.getTable().getSize())
                    .from(request.getTable().getStartIndex());

            SearchRequest searchRequest = new SearchRequest()
                    .indices(iocIndices.toArray(new String[0]))
                    .source(searchSourceBuilder)
                    .preference(Preference.PRIMARY_FIRST.type());

            client.search(searchRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse searchResponse) {
                    if (searchResponse.isTimedOut()) {
                        onFailures(new OpenSearchStatusException("Search request timed out", RestStatus.REQUEST_TIMEOUT));
                    }

                    getFindingsCount(searchResponse);
                }

                @Override
                public void onFailure(Exception e) {
                    if (e instanceof IndexNotFoundException) {
                        // If no IOC system indexes are found, return empty list response
                        listener.onResponse(ListIOCsActionResponse.EMPTY_RESPONSE);
                    } else {
                        log.error("Failed to list IOCs.", e);
                        listener.onFailure(SecurityAnalyticsException.wrap(e));
                    }
                }
            });
        }

        private void getFindingsCount(SearchResponse iocSearchResponse) {
            // Concurrently compiling a separate list of IOC IDs to create the subsequent findings count searchRequest
            Set<String> iocIds = new HashSet<>();
            List<STIX2IOCDto> iocs = new ArrayList<>();
            Arrays.stream(iocSearchResponse.getHits().getHits())
                    .forEach(hit -> {
                        try {
                            XContentParser xcp = XContentType.JSON.xContent().createParser(
                                    xContentRegistry,
                                    LoggingDeprecationHandler.INSTANCE,
                                    hit.getSourceAsString());
                            xcp.nextToken();

                            STIX2IOCDto ioc = STIX2IOCDto.parse(xcp, hit.getId(), hit.getVersion());

                            iocIds.add(ioc.getId());
                            iocs.add(ioc);
                        } catch (Exception e) {
                            log.error(
                                    () -> new ParameterizedMessage("Failed to parse IOC doc from hit {}", hit.getId()), e
                            );
                        }
                    });

            // Create an aggregation query that will group by the IOC IDs in the findings
            SearchSourceBuilder findingsCountSourceBuilder = new SearchSourceBuilder()
                    .fetchSource(false)
                    .trackTotalHits(true)
                    .query(QueryBuilders.termsQuery(IOC_ID_KEYWORD_FIELD, iocIds))
                    .size(0)
                    .aggregation(
                            AggregationBuilders
                                    .terms(IOC_COUNT_AGG_NAME)
                                    .field(IOC_ID_KEYWORD_FIELD)
                                    .size(iocIds.size())
                    );

            iocFindingService.search(findingsCountSourceBuilder, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse findingsSearchResponse) {
                    Map<String, Integer> iocIdToNumFindings = new HashMap<>();

                    // Retrieve and store the counts from the aggregation response
                    Aggregations aggregations = findingsSearchResponse.getAggregations();
                    if (aggregations != null) {
                        Terms iocIdCount = aggregations.get(IOC_COUNT_AGG_NAME);
                        if (iocIdCount != null) {
                            for (Terms.Bucket bucket : iocIdCount.getBuckets()) {
                                String iocId = bucket.getKeyAsString();
                                long findingCount = bucket.getDocCount();
                                iocIdToNumFindings.put(iocId, (int) findingCount);
                            }
                        }
                    }

                    // Iterate through each IOC returned by the SearchRequest to create the detailed model for response
                    List<DetailedSTIX2IOCDto> iocDetails = new ArrayList<>();
                    iocs.forEach((ioc) -> {
                        Integer numFindings = iocIdToNumFindings.getOrDefault(ioc.getId(), 0);
                        iocDetails.add(new DetailedSTIX2IOCDto(ioc, numFindings));
                    });

                    // Return API response
                    onOperation(new ListIOCsActionResponse(iocSearchResponse.getHits().getTotalHits().value, iocDetails));
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to get IOC findings count:", e);
                    listener.onFailure(SecurityAnalyticsException.wrap(e));
                }
            });
        }
        private void onOperation(ListIOCsActionResponse response) {
            this.response.set(response);
            if (counter.compareAndSet(false, true)) {
                finishHim(response, null);
            }
        }

        private void onFailures(Exception t) {
            if (counter.compareAndSet(false, true)) {
                finishHim(null, t);
            }
        }

        private void finishHim(ListIOCsActionResponse response, Exception t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null) {
                    if (t instanceof OpenSearchStatusException) {
                        throw t;
                    }
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return response;
                }
            }));
        }
    }

    private SearchSourceBuilder getFeedsSearchSourceBuilder(List<String> configIds) {
        if (false == configIds.isEmpty()) {
            BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery();
            for (String configId : configIds) {
                queryBuilder.should(QueryBuilders.matchQuery("_id", configId));
            }
            return new SearchSourceBuilder().query(queryBuilder).size(9999);
        } else {
            BoolQueryBuilder stateQueryBuilder = QueryBuilders.boolQuery()
                    .should(QueryBuilders.matchQuery(getStateFieldName(), REFRESHING.toString()))
                    .should(QueryBuilders.matchQuery(getStateFieldName(), AVAILABLE.toString()));
            return new SearchSourceBuilder().query(stateQueryBuilder).size(9999);
        }
    }
}
