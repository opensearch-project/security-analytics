package org.opensearch.securityanalytics.threatIntel.iocscan.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.DocWriteRequest;
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
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.model.threatintel.BaseEntity;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides generic CRUD implementations for entity that is stored in system index. Provides generic implementation
 * of system index too.
 */
public abstract class BaseEntityCrudService<Entity extends BaseEntity> {
    private static final Logger log = LogManager.getLogger(BaseEntityCrudService.class);
    private final Client client;
    private final ClusterService clusterService;


    public BaseEntityCrudService(Client client, ClusterService clusterService, NamedXContentRegistry xContentRegistry) {
        this.client = client;
        this.clusterService = clusterService;
    }

    public void bulkIndexEntities(List<Entity> entityList,
                                  ActionListener<Void> actionListener) {
        try {
            Integer batchSize = this.clusterService.getClusterSettings().get(SecurityAnalyticsSettings.BATCH_SIZE);
            createIndexIfNotExists(ActionListener.wrap(
                    r -> {
                        List<BulkRequest> bulkRequestList = new ArrayList<>();
                        BulkRequest bulkRequest = new BulkRequest(getIndexName());
                        for (int i = 0; i < entityList.size(); i++) {
                            Entity entity = entityList.get(i);
                            try {
                                IndexRequest indexRequest = new IndexRequest(getIndexName())
                                        .id(entity.getId())
                                        .source(entity.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                                        .opType(DocWriteRequest.OpType.CREATE);
                                bulkRequest.add(indexRequest);
                                if (
                                        bulkRequest.requests().size() == batchSize
                                                && i != entityList.size() - 1 // final bulk request will be added outside for loop with refresh policy none
                                ) {
                                    bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.NONE);
                                    bulkRequestList.add(bulkRequest);
                                    bulkRequest = new BulkRequest();
                                }
                            } catch (IOException e) {
                                log.error(String.format("Failed to create index request for %s moving on to next", getEntityName()), e);
                            }
                        }
                        bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                        bulkRequestList.add(bulkRequest);
                        GroupedActionListener<BulkResponse> groupedListener = new GroupedActionListener<>(ActionListener.wrap(bulkResponses -> {
                            int idx = 0;
                            for (BulkResponse response : bulkResponses) {
                                BulkRequest request = bulkRequestList.get(idx);
                                if (response.hasFailures()) {
                                    log.error("Failed to bulk index {} {}s. Failure: {}", request.batchSize(), getEntityName(), response.buildFailureMessage());
                                }
                            }
                            actionListener.onResponse(null);
                        }, actionListener::onFailure), bulkRequestList.size());
                        for (BulkRequest req : bulkRequestList) {
                            try {
                                client.bulk(req, groupedListener); //todo why stash context here?
                            } catch (Exception e) {
                                log.error(
                                        () -> new ParameterizedMessage("Failed to bulk save {} {}.", req.batchSize(), getEntityName()),
                                        e);
                            }
                        }
                    }, e -> {
                        log.error(() -> new ParameterizedMessage("Failed to create System Index {}", getIndexName()), e);
                        actionListener.onFailure(e);
                    }));


        } catch (Exception e) {
            log.error("Exception saving the threat intel source config in index", e);
            actionListener.onFailure(e);
        }
    }

    public void searchEntities(SearchSourceBuilder searchSourceBuilder, final ActionListener<SearchResponse> actionListener) {
        SearchRequest searchRequest = new SearchRequest()
                .source(searchSourceBuilder)
                .indices(getIndexName());
        client.search(searchRequest, actionListener);
    }

    public void createIndexIfNotExists(final ActionListener<Void> listener) {
        // check if job index exists
        try {
            if (clusterService.state().metadata().hasIndex(getIndexName()) == true) {
                listener.onResponse(null);
                return;
            }
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(getIndexName()).mapping(getIndexMapping())
                    .settings(getIndexSettings());
            client.admin().indices().create(createIndexRequest, ActionListener.wrap(
                    r -> {
                        log.debug("Ioc match index created");
                        listener.onResponse(null);
                    }, e -> {
                        if (e instanceof ResourceAlreadyExistsException) {
                            log.debug("index {} already exist", getIndexMapping());
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

    protected abstract String getIndexMapping();

    protected abstract String getIndexName();

    public abstract String getEntityName();

    protected Settings.Builder getIndexSettings() {
        return Settings.builder().put("index.hidden", true);
    }
}
