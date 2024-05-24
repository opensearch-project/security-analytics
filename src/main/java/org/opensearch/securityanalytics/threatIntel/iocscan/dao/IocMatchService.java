package org.opensearch.securityanalytics.threatIntel.iocscan.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.model.threatintel.IocMatch;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.threadpool.ThreadPool;

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
public class IocMatchService {
    //TODO manage index rollover
    public static final String INDEX_NAME = ".opensearch-sap-iocmatch";
    private static final Logger log = LogManager.getLogger(IocMatchService.class);
    private final Client client;
    private final ClusterService clusterService;

    public IocMatchService(final Client client, final ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    public void indexIocMatches(List<IocMatch> iocMatches,
                                final ActionListener<Void> actionListener) {
        try {
            Integer batchSize = this.clusterService.getClusterSettings().get(SecurityAnalyticsSettings.BATCH_SIZE);
            createIndexIfNotExists(ActionListener.wrap(
                    r -> {
                        List<BulkRequest> bulkRequestList = new ArrayList<>();
                        BulkRequest bulkRequest = new BulkRequest(INDEX_NAME);
                        for (int i = 0; i < iocMatches.size(); i++) {
                            IocMatch iocMatch = iocMatches.get(i);
                            try {
                                IndexRequest indexRequest = new IndexRequest(INDEX_NAME)
                                        .source(iocMatch.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                                        .opType(DocWriteRequest.OpType.CREATE);
                                bulkRequest.add(indexRequest);
                                if (
                                        bulkRequest.requests().size() == batchSize
                                                && i != iocMatches.size() - 1 // final bulk request will be added outside for loop with refresh policy none
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

    private String getIndexMapping() {
        try {
            try (InputStream is = IocMatchService.class.getResourceAsStream("/mappings/ioc_match_mapping.json")) {
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
     * Mapping: /mappings/ioc_match_mapping.json
     *
     * @param listener setup listener
     */
    public void createIndexIfNotExists(final ActionListener<Void> listener) {
        // check if job index exists
        try {
            if (clusterService.state().metadata().hasIndex(INDEX_NAME) == true) {
                listener.onResponse(null);
                return;
            }
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(INDEX_NAME).mapping(getIndexMapping())
                    .settings(SecurityAnalyticsPlugin.TIF_JOB_INDEX_SETTING);
            client.admin().indices().create(createIndexRequest, ActionListener.wrap(
                    r -> {
                        log.debug("Ioc match index created");
                        listener.onResponse(null);
                    }, e -> {
                        if (e instanceof ResourceAlreadyExistsException) {
                            log.debug("index {} already exist", INDEX_NAME);
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
}