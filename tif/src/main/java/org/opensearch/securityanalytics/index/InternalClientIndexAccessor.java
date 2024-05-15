//package org.opensearch.securityanalytics.index;
//
//import org.opensearch.action.admin.indices.alias.Alias;
//import org.opensearch.action.admin.indices.alias.get.GetAliasesRequest;
//import org.opensearch.action.admin.indices.alias.get.GetAliasesResponse;
//import org.opensearch.action.admin.indices.create.CreateIndexRequest;
//import org.opensearch.action.admin.indices.create.CreateIndexResponse;
//import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
//import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
//import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
//import org.opensearch.action.bulk.BulkRequest;
//import org.opensearch.action.bulk.BulkResponse;
//import org.opensearch.action.support.master.AcknowledgedResponse;
//import org.opensearch.client.Client;
//import org.opensearch.common.action.ActionFuture;
//import org.opensearch.common.settings.Settings;
//import org.opensearch.core.common.unit.ByteSizeValue;
//import org.opensearch.index.query.QueryBuilder;
//import org.opensearch.index.reindex.BulkByScrollResponse;
//import org.opensearch.index.reindex.DeleteByQueryAction;
//import org.opensearch.index.reindex.DeleteByQueryRequestBuilder;
//import org.opensearch.securityanalytics.exceptions.IndexAccessorException;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//
//import java.util.concurrent.TimeUnit;
//
//public class InternalClientIndexAccessor implements IndexAccessor {
//    private static final Logger log = LoggerFactory.getLogger(InternalClientIndexAccessor.class);
//
//    private static final long REQUEST_TIMEOUT_SECONDS = 30L;
//    private static final TimeUnit REQUEST_TIMEOUT_TIME_UNIT = TimeUnit.SECONDS;
//
//    private final Client client;
//
//    public InternalClientIndexAccessor(final Client client) {
//        this.client = client;
//    }
//
//    @Override
//    public void createIndex(final String aliasName, final Settings settings) {
//        final boolean doesAliasExist = doesAliasExist(aliasName);
//        if (doesAliasExist) {
//            log.debug("Alias with name {} already exists. Skipping index creation", aliasName);
//            return;
//        }
//
//        final boolean doesIndexExist = doesIndexExist(indexName);
//        if (doesIndexExist) {
//            log.debug("Index with name {} already exists. Skipping creation", indexName);
//            return;
//        }
//
//        doCreateIndex(indexName, aliasName, settings);
//    }
//
//    private boolean doesAliasExist(final String aliasName) {
//        if (aliasName == null) {
//            return false;
//        }
//
//        final GetAliasesRequest getAliasesRequest = new GetAliasesRequest(aliasName);
//        try {
//            final ActionFuture<GetAliasesResponse> getAliasesResponseFuture = client.admin().indices().getAliases(getAliasesRequest);
//            final GetAliasesResponse getAliasesResponse = getAliasesResponseFuture.actionGet(REQUEST_TIMEOUT_SECONDS, REQUEST_TIMEOUT_TIME_UNIT);
//
//            return getAliasesResponse.getAliases().containsKey(aliasName);
//        } catch (final Exception e) {
//            throw new IndexAccessorException("Failed to get aliases for " + aliasName, e);
//        }
//    }
//
//    private boolean doesIndexExist(final String indexName) {
//        final IndicesExistsRequest indicesExistsRequest = new IndicesExistsRequest(indexName);
//        try {
//            final ActionFuture<IndicesExistsResponse> indicesExistsResponseFuture = client.admin().indices().exists(indicesExistsRequest);
//            final IndicesExistsResponse indicesExistsResponse = indicesExistsResponseFuture.actionGet(REQUEST_TIMEOUT_SECONDS, REQUEST_TIMEOUT_TIME_UNIT);
//
//            return indicesExistsResponse.isExists();
//        } catch (final Exception e) {
//            throw new IndexAccessorException("Failed to check if index exists with name: " + indexName, e);
//        }
//    }
//
//    private void doCreateIndex(final String indexName, final String aliasName, final Settings settings) {
//        final CreateIndexRequest createIndexRequest = new CreateIndexRequest(indexName);
//        createIndexRequest.settings(settings);
//        createIndexRequest.alias(new Alias(aliasName).writeIndex(true));
//
//        try {
//            final ActionFuture<CreateIndexResponse> createIndexResponseFuture = client.admin().indices().create(createIndexRequest);
//            createIndexResponseFuture.actionGet(REQUEST_TIMEOUT_SECONDS, REQUEST_TIMEOUT_TIME_UNIT);
//        } catch (final Exception e) {
//            throw new IndexAccessorException("Failed to create index with name: " + indexName, e);
//        }
//    }
//
//    @Override
//    public void deleteIndex(final String indexName) {
//        final DeleteIndexRequest deleteIndexRequest = new DeleteIndexRequest(indexName);
//        try {
//            final ActionFuture<AcknowledgedResponse> deleteIndexResponseFuture = client.admin().indices().delete(deleteIndexRequest);
//            final AcknowledgedResponse deleteIndexResponse = deleteIndexResponseFuture.actionGet(REQUEST_TIMEOUT_SECONDS, REQUEST_TIMEOUT_TIME_UNIT);
//
//            if (!deleteIndexResponse.isAcknowledged()) {
//                throw new IndexAccessorException("Delete index request was not acknowledged for index with name: " + indexName);
//            }
//        } catch (final Exception e) {
//            throw new IndexAccessorException("Failed to delete index with name: " + indexName, e);
//        }
//    }
//
//    @Override
//    public void createRolloverAlias(final String aliasName, final ByteSizeValue indexSizeRolloverValue, final Settings settings) {
//
//    }
//
//    @Override
//    public void deleteAlias(final String aliasName) {
//
//    }
//
//    @Override
//    public BulkByScrollResponse deleteByQuery(final String indexName, final QueryBuilder queryBuilder) {
//        final DeleteByQueryRequestBuilder deleteByQueryRequestBuilder = new DeleteByQueryRequestBuilder(client, DeleteByQueryAction.INSTANCE)
//                .source(indexName)
//                .filter(queryBuilder)
//                .refresh(true);
//
//        try {
//            final ActionFuture<BulkByScrollResponse> deleteByQueryResponseFuture = deleteByQueryRequestBuilder.execute();
//            return deleteByQueryResponseFuture.actionGet(REQUEST_TIMEOUT_SECONDS, REQUEST_TIMEOUT_TIME_UNIT);
//        } catch (final Exception e) {
//            throw new IndexAccessorException("Failed to delete by query", e);
//        }
//    }
//
//    @Override
//    public BulkResponse bulk(final BulkRequest bulkRequest) {
//        try {
//            final ActionFuture<BulkResponse> bulkResponseFuture = client.bulk(bulkRequest);
//            return bulkResponseFuture.actionGet(REQUEST_TIMEOUT_SECONDS, REQUEST_TIMEOUT_TIME_UNIT);
//        } catch (final Exception e) {
//            throw new IndexAccessorException("Failed to execute bulk request", e);
//        }
//    }
//}
