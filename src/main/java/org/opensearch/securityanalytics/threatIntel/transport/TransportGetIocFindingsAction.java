/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.transport;

import org.apache.lucene.search.join.ScoreMode;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.search.SearchResponse;
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
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.Operator;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.search.sort.FieldSortBuilder;
import org.opensearch.search.sort.SortBuilders;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.securityanalytics.model.threatintel.IocFinding;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.GetIocFindingsAction;
import org.opensearch.securityanalytics.threatIntel.action.GetIocFindingsRequest;
import org.opensearch.securityanalytics.threatIntel.action.GetIocFindingsResponse;
import org.opensearch.securityanalytics.threatIntel.iocscan.dao.IocFindingService;
import org.opensearch.securityanalytics.transport.SecureTransportAction;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class TransportGetIocFindingsAction extends HandledTransportAction<GetIocFindingsRequest, GetIocFindingsResponse> implements SecureTransportAction {

    private final IocFindingService iocFindingService;

    private final ClusterService clusterService;

    private final Settings settings;

    private final NamedXContentRegistry xContentRegistry;
    private final ThreadPool threadPool;

    private volatile Boolean filterByEnabled;

    @Inject
    public TransportGetIocFindingsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            ClusterService clusterService,
            Settings settings,
            NamedXContentRegistry xContentRegistry,
            Client client
    ) {
        super(GetIocFindingsAction.NAME, transportService, actionFilters, GetIocFindingsRequest::new);
        this.settings = settings;
        this.clusterService = clusterService;
        this.xContentRegistry = xContentRegistry;
        this.threadPool = client.threadPool();
        this.iocFindingService = new IocFindingService(client, this.clusterService, xContentRegistry);
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);
        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);
    }

    @Override
    protected void doExecute(Task task, GetIocFindingsRequest request, ActionListener<GetIocFindingsResponse> actionListener) {
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            actionListener.onFailure(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN));
            return;
        }
        Table tableProp = request.getTable();
        FieldSortBuilder sortBuilder = SortBuilders
                .fieldSort(tableProp.getSortString())
                .order(SortOrder.fromString(tableProp.getSortOrder()));
        if (tableProp.getMissing() != null && !tableProp.getMissing().isBlank()) {
            sortBuilder.missing(tableProp.getMissing());
        }

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                .sort(sortBuilder)
                .size(tableProp.getSize())
                .from(tableProp.getStartIndex())
                .fetchSource(new FetchSourceContext(true, Strings.EMPTY_ARRAY, Strings.EMPTY_ARRAY))
                .seqNoAndPrimaryTerm(true)
                .version(true);

        BoolQueryBuilder queryBuilder = QueryBuilders.boolQuery();
        List<String> findingIds = request.getFindingIds();

        if (findingIds != null && !findingIds.isEmpty()) {
            queryBuilder.filter(QueryBuilders.termsQuery("id", findingIds));
        }

        List<String> iocIds = request.getIocIds();
        if (iocIds != null && !iocIds.isEmpty()) {
            queryBuilder.filter(QueryBuilders.termsQuery("ioc_feed_ids.ioc_id", iocIds));
        }

        Instant startTime = request.getStartTime();
        Instant endTime = request.getEndTime();
        if (startTime != null && endTime != null) {
            long startTimeMillis = startTime.toEpochMilli();
            long endTimeMillis = endTime.toEpochMilli();
            QueryBuilder timeRangeQuery = QueryBuilders.rangeQuery("timestamp")
                    .from(startTimeMillis) // Greater than or equal to start time
                    .to(endTimeMillis); // Less than or equal to end time
            queryBuilder.filter(timeRangeQuery);
        }

        if (tableProp.getSearchString() != null && !tableProp.getSearchString().isBlank()) {
            queryBuilder.should(QueryBuilders
                    .queryStringQuery(tableProp.getSearchString())
            ).should(
                    QueryBuilders.nestedQuery(
                            "queries",
                            QueryBuilders.boolQuery()
                                    .must(
                                            QueryBuilders.queryStringQuery(tableProp.getSearchString())
                                    ),
                            ScoreMode.Avg
                    )
            );
        }
        searchSourceBuilder.query(queryBuilder).trackTotalHits(true);

        this.threadPool.getThreadContext().stashContext();
        iocFindingService.search(searchSourceBuilder, new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse searchResponse) {
                try {
                    long totalIocFindingsCount = searchResponse.getHits().getTotalHits().value;
                    List<IocFinding> iocFindings = new ArrayList<>();

                    for (SearchHit hit : searchResponse.getHits()) {
                        XContentParser xcp = XContentType.JSON.xContent()
                                .createParser(xContentRegistry, LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString());
                        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.nextToken(), xcp);
                        IocFinding iocFinding = IocFinding.parse(xcp);
                        iocFindings.add(iocFinding);
                    }
                    actionListener.onResponse(new GetIocFindingsResponse((int) totalIocFindingsCount, iocFindings));
                } catch (Exception ex) {
                    this.onFailure(ex);
                }
            }

            @Override
            public void onFailure(Exception e) {
                if (e instanceof IndexNotFoundException) {
                    actionListener.onResponse(new GetIocFindingsResponse(0, List.of()));
                    return;
                }
                actionListener.onFailure(e);
            }
        });
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }
}