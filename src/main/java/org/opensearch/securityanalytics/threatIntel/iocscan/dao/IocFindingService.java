package org.opensearch.securityanalytics.threatIntel.iocscan.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.model.IocFinding;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.GetIocFindingsResponse;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Data layer to perform CRUD operations for threat intel ioc match : store in system index.
 */
public class IocFindingService {
    //TODO manage index rollover
    public static final String IOC_FINDING_ALIAS_NAME = ".opensearch-sap-ioc-findings";

    public static final String IOC_FINDING_INDEX_PATTERN = "<.opensearch-sap-ioc-findings-history-{now/d}-1>";

    public static final String IOC_FINDING_INDEX_PATTERN_REGEXP = ".opensearch-sap-ioc-findings*";

    private static final Logger log = LogManager.getLogger(IocFindingService.class);
    private final Client client;
    private final ClusterService clusterService;

    private final NamedXContentRegistry xContentRegistry;

    public IocFindingService(final Client client, final ClusterService clusterService, final NamedXContentRegistry xContentRegistry) {
        this.client = client;
        this.clusterService = clusterService;
        this.xContentRegistry = xContentRegistry;
    }

    public void indexIocMatches(List<IocFinding> iocFindings,
                                final ActionListener<Void> actionListener) {
        try {
            Integer batchSize = this.clusterService.getClusterSettings().get(SecurityAnalyticsSettings.BATCH_SIZE);
            createIndexIfNotExists(ActionListener.wrap(
                    r -> {
                        List<BulkRequest> bulkRequestList = new ArrayList<>();
                        BulkRequest bulkRequest = new BulkRequest(IOC_FINDING_ALIAS_NAME);
                        for (int i = 0; i < iocFindings.size(); i++) {
                            IocFinding iocFinding = iocFindings.get(i);
                            try {
                                IndexRequest indexRequest = new IndexRequest(IOC_FINDING_ALIAS_NAME)
                                        .source(iocFinding.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                                        .opType(DocWriteRequest.OpType.CREATE);
                                bulkRequest.add(indexRequest);
                                if (
                                        bulkRequest.requests().size() == batchSize
                                                && i != iocFindings.size() - 1 // final bulk request will be added outside for loop with refresh policy none
                                ) {
                                    bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.NONE);
                                    bulkRequestList.add(bulkRequest);
                                    bulkRequest = new BulkRequest();
                                }
                            } catch (IOException e) {
                                log.error(String.format("Failed to create index request for ioc match %s moving on to next"), e);
                            }
                        }
                        bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                        bulkRequestList.add(bulkRequest);
                        GroupedActionListener<BulkResponse> groupedListener = new GroupedActionListener<>(ActionListener.wrap(bulkResponses -> {
                            int idx = 0;
                            for (BulkResponse response : bulkResponses) {
                                BulkRequest request = bulkRequestList.get(idx);
                                if (response.hasFailures()) {
                                    log.error("Failed to bulk index {} Ioc Matches. Failure: {}", request.batchSize(), response.buildFailureMessage());
                                }
                            }
                            actionListener.onResponse(null);
                        }, actionListener::onFailure), bulkRequestList.size());
                        for (BulkRequest req : bulkRequestList) {
                            try {
                                client.bulk(req, groupedListener); //todo why stash context here?
                            } catch (Exception e) {
                                log.error("Failed to save ioc matches.", e);
                            }
                        }
                    }, e -> {
                        log.error("Failed to create System Index");
                        actionListener.onFailure(e);
                    }));


        } catch (Exception e) {
            log.error("Exception saving the threat intel source config in index", e);
            actionListener.onFailure(e);
        }
    }

    public static String getIndexMapping() {
        try {
            try (InputStream is = IocFindingService.class.getResourceAsStream("/mappings/ioc_finding_mapping.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Failed to get the threat intel ioc match index mapping", e);
            throw new SecurityAnalyticsException("Failed to get the threat intel ioc match index mapping", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }

    /**
     * Index name: .opensearch-sap-iocmatch
     * Mapping: /mappings/ioc_finding_mapping.json
     *
     * @param listener setup listener
     */
    public void createIndexIfNotExists(final ActionListener<Void> listener) {
        // check if job index exists
        try {
            if (clusterService.state().metadata().hasAlias(IOC_FINDING_ALIAS_NAME) == true) {
                listener.onResponse(null);
                return;
            }
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(IOC_FINDING_INDEX_PATTERN).mapping(getIndexMapping())
                    .settings(SecurityAnalyticsPlugin.TIF_JOB_INDEX_SETTING).alias(new Alias(IOC_FINDING_ALIAS_NAME));
            client.admin().indices().create(createIndexRequest, ActionListener.wrap(
                    r -> {
                        log.debug("Ioc match index created");
                        listener.onResponse(null);
                    }, e -> {
                        if (e instanceof ResourceAlreadyExistsException) {
                            log.debug("index {} already exist", IOC_FINDING_INDEX_PATTERN);
                            listener.onResponse(null);
                            return;
                        }
                        log.error("Failed to create security analytics threat intel job index", e);
                        listener.onFailure(e);
                    }
            ));
        } catch (Exception e) {
            log.error("Failure in creating ioc_match index", e);
            listener.onFailure(e);
        }
    }

    public void searchIocMatches(SearchSourceBuilder searchSourceBuilder, final ActionListener<GetIocFindingsResponse> actionListener) {
        createIndexIfNotExists(ActionListener.wrap(
                r -> {
        SearchRequest searchRequest = new SearchRequest()
                .source(searchSourceBuilder)
                .indices(IOC_FINDING_ALIAS_NAME);

        client.search(searchRequest, new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse searchResponse) {
                try {
                    long totalIocFindingsCount = searchResponse.getHits().getTotalHits().value;
                    List<IocFinding> iocFindings = new ArrayList<>();

                    for (SearchHit hit: searchResponse.getHits()) {
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
        }, e -> {
                    log.error("Failed to create System Index");
                    actionListener.onFailure(e);
        }));
    }
}