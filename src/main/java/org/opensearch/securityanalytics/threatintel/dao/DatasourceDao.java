/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.dao;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.get.MultiGetItemResponse;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.Datasource;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.DatasourceExtension;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

/**
 * Data access object for datasource
 */
public class DatasourceDao {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private static final Integer MAX_SIZE = 1000;
    private final Client client;
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;

    public DatasourceDao(final Client client, final ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
    }

    /**
     * Create datasource index
     *
     * @param stepListener setup listener
     */
    public void createIndexIfNotExists(final StepListener<Void> stepListener) {
        if (clusterService.state().metadata().hasIndex(DatasourceExtension.JOB_INDEX_NAME) == true) {
            stepListener.onResponse(null);
            return;
        }
        final CreateIndexRequest createIndexRequest = new CreateIndexRequest(DatasourceExtension.JOB_INDEX_NAME).mapping(getIndexMapping())
                .settings(DatasourceExtension.INDEX_SETTING);
        StashedThreadContext.run(client, () -> client.admin().indices().create(createIndexRequest, new ActionListener<>() {
            @Override
            public void onResponse(final CreateIndexResponse createIndexResponse) {
                stepListener.onResponse(null);
            }

            @Override
            public void onFailure(final Exception e) {
                if (e instanceof ResourceAlreadyExistsException) {
                    log.info("index[{}] already exist", DatasourceExtension.JOB_INDEX_NAME);
                    stepListener.onResponse(null);
                    return;
                }
                stepListener.onFailure(e);
            }
        }));
    }

    private String getIndexMapping() {
        try {
            try (InputStream is = DatasourceDao.class.getResourceAsStream("/mappings/threatintel_datasource.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Runtime exception", e);
            throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
        }
    }

    /**
     * Update datasource in an index {@code DatasourceExtension.JOB_INDEX_NAME}
     * @param datasource the datasource
     * @return index response
     */
    public IndexResponse updateDatasource(final Datasource datasource) {
        datasource.setLastUpdateTime(Instant.now());
        return StashedThreadContext.run(client, () -> {
            try {
                return client.prepareIndex(DatasourceExtension.JOB_INDEX_NAME)
                        .setId(datasource.getName())
                        .setOpType(DocWriteRequest.OpType.INDEX)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .setSource(datasource.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                        .execute()
                        .actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT));
            } catch (IOException e) {
                throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
            }
        });
    }

    /**
     * Update datasources in an index {@code DatasourceExtension.JOB_INDEX_NAME}
     * @param datasources the datasources
     * @param listener action listener
     */
    public void updateDatasource(final List<Datasource> datasources, final ActionListener<BulkResponse> listener) {
        BulkRequest bulkRequest = new BulkRequest();
        datasources.stream().map(datasource -> {
            datasource.setLastUpdateTime(Instant.now());
            return datasource;
        }).map(this::toIndexRequest).forEach(indexRequest -> bulkRequest.add(indexRequest));
        StashedThreadContext.run(client, () -> client.bulk(bulkRequest, listener));
    }

    private IndexRequest toIndexRequest(Datasource datasource) {
        try {
            IndexRequest indexRequest = new IndexRequest();
            indexRequest.index(DatasourceExtension.JOB_INDEX_NAME);
            indexRequest.id(datasource.getName());
            indexRequest.opType(DocWriteRequest.OpType.INDEX);
            indexRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
            indexRequest.source(datasource.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            return indexRequest;
        } catch (IOException e) {
            throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
        }
    }

    /**
     * Put datasource in an index {@code DatasourceExtension.JOB_INDEX_NAME}
     *
     * @param datasource the datasource
     * @param listener the listener
     */
    public void putDatasource(final Datasource datasource, final ActionListener listener) {
        datasource.setLastUpdateTime(Instant.now());
        StashedThreadContext.run(client, () -> {
            try {
                client.prepareIndex(DatasourceExtension.JOB_INDEX_NAME)
                        .setId(datasource.getName())
                        .setOpType(DocWriteRequest.OpType.CREATE)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .setSource(datasource.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                        .execute(listener);
            } catch (IOException e) {
                throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
            }
        });
    }

    /**
     * Delete datasource in an index {@code DatasourceExtension.JOB_INDEX_NAME}
     *
     * @param datasource the datasource
     *
     */
    public void deleteDatasource(final Datasource datasource) {
        DeleteResponse response = client.prepareDelete()
                .setIndex(DatasourceExtension.JOB_INDEX_NAME)
                .setId(datasource.getName())
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .execute()
                .actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT));

        if (response.status().equals(RestStatus.OK)) {
            log.info("deleted datasource[{}] successfully", datasource.getName());
        } else if (response.status().equals(RestStatus.NOT_FOUND)) {
            throw new ResourceNotFoundException("datasource[{}] does not exist", datasource.getName());
        } else {
            throw new OpenSearchException("failed to delete datasource[{}] with status[{}]", datasource.getName(), response.status());
        }
    }

    /**
     * Get datasource from an index {@code DatasourceExtension.JOB_INDEX_NAME}
     * @param name the name of a datasource
     * @return datasource
     * @throws IOException exception
     */
    public Datasource getDatasource(final String name) throws IOException {
        GetRequest request = new GetRequest(DatasourceExtension.JOB_INDEX_NAME, name);
        GetResponse response;
        try {
            response = StashedThreadContext.run(client, () -> client.get(request).actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT)));
            if (response.isExists() == false) {
                log.error("Datasource[{}] does not exist in an index[{}]", name, DatasourceExtension.JOB_INDEX_NAME);
                return null;
            }
        } catch (IndexNotFoundException e) {
            log.error("Index[{}] is not found", DatasourceExtension.JOB_INDEX_NAME);
            return null;
        }

        XContentParser parser = XContentHelper.createParser(
                NamedXContentRegistry.EMPTY,
                LoggingDeprecationHandler.INSTANCE,
                response.getSourceAsBytesRef()
        );
        return Datasource.PARSER.parse(parser, null);
    }

    /**
     * Get datasource from an index {@code DatasourceExtension.JOB_INDEX_NAME}
     * @param name the name of a datasource
     * @param actionListener the action listener
     */
    public void getDatasource(final String name, final ActionListener<Datasource> actionListener) {
        GetRequest request = new GetRequest(DatasourceExtension.JOB_INDEX_NAME, name);
        StashedThreadContext.run(client, () -> client.get(request, new ActionListener<>() {
            @Override
            public void onResponse(final GetResponse response) {
                if (response.isExists() == false) {
                    actionListener.onResponse(null);
                    return;
                }

                try {
                    XContentParser parser = XContentHelper.createParser(
                            NamedXContentRegistry.EMPTY,
                            LoggingDeprecationHandler.INSTANCE,
                            response.getSourceAsBytesRef()
                    );
                    actionListener.onResponse(Datasource.PARSER.parse(parser, null));
                } catch (IOException e) {
                    actionListener.onFailure(e);
                }
            }

            @Override
            public void onFailure(final Exception e) {
                actionListener.onFailure(e);
            }
        }));
    }

    /**
     * Get datasources from an index {@code DatasourceExtension.JOB_INDEX_NAME}
     * @param names the array of datasource names
     * @param actionListener the action listener
     */
    public void getDatasources(final String[] names, final ActionListener<List<Datasource>> actionListener) {
        StashedThreadContext.run(
                client,
                () -> client.prepareMultiGet()
                        .add(DatasourceExtension.JOB_INDEX_NAME, names)
                        .execute(createGetDataSourceQueryActionLister(MultiGetResponse.class, actionListener))
        );
    }

    /**
     * Get all datasources up to {@code MAX_SIZE} from an index {@code DatasourceExtension.JOB_INDEX_NAME}
     * @param actionListener the action listener
     */
    public void getAllDatasources(final ActionListener<List<Datasource>> actionListener) {
        StashedThreadContext.run(
                client,
                () -> client.prepareSearch(DatasourceExtension.JOB_INDEX_NAME)
                        .setQuery(QueryBuilders.matchAllQuery())
                        .setPreference(Preference.PRIMARY.type())
                        .setSize(MAX_SIZE)
                        .execute(createGetDataSourceQueryActionLister(SearchResponse.class, actionListener))
        );
    }

    /**
     * Get all datasources up to {@code MAX_SIZE} from an index {@code DatasourceExtension.JOB_INDEX_NAME}
     */
    public List<Datasource> getAllDatasources() {
        SearchResponse response = StashedThreadContext.run(
                client,
                () -> client.prepareSearch(DatasourceExtension.JOB_INDEX_NAME)
                        .setQuery(QueryBuilders.matchAllQuery())
                        .setPreference(Preference.PRIMARY.type())
                        .setSize(MAX_SIZE)
                        .execute()
                        .actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT))
        );

        List<BytesReference> bytesReferences = toBytesReferences(response);
        return bytesReferences.stream().map(bytesRef -> toDatasource(bytesRef)).collect(Collectors.toList());
    }

    private <T> ActionListener<T> createGetDataSourceQueryActionLister(
            final Class<T> response,
            final ActionListener<List<Datasource>> actionListener
    ) {
        return new ActionListener<T>() {
            @Override
            public void onResponse(final T response) {
                try {
                    List<BytesReference> bytesReferences = toBytesReferences(response);
                    List<Datasource> datasources = bytesReferences.stream()
                            .map(bytesRef -> toDatasource(bytesRef))
                            .collect(Collectors.toList());
                    actionListener.onResponse(datasources);
                } catch (Exception e) {
                    actionListener.onFailure(e);
                }
            }

            @Override
            public void onFailure(final Exception e) {
                actionListener.onFailure(e);
            }
        };
    }

    private List<BytesReference> toBytesReferences(final Object response) {
        if (response instanceof SearchResponse) {
            SearchResponse searchResponse = (SearchResponse) response;
            return Arrays.stream(searchResponse.getHits().getHits()).map(SearchHit::getSourceRef).collect(Collectors.toList());
        } else if (response instanceof MultiGetResponse) {
            MultiGetResponse multiGetResponse = (MultiGetResponse) response;
            return Arrays.stream(multiGetResponse.getResponses())
                    .map(MultiGetItemResponse::getResponse)
                    .filter(Objects::nonNull)
                    .filter(GetResponse::isExists)
                    .map(GetResponse::getSourceAsBytesRef)
                    .collect(Collectors.toList());
        } else {
            throw new OpenSearchException("No supported instance type[{}] is provided", response.getClass());
        }
    }

    private Datasource toDatasource(final BytesReference bytesReference) {
        try {
            XContentParser parser = XContentHelper.createParser(
                    NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE,
                    bytesReference
            );
            return Datasource.PARSER.parse(parser, null);
        } catch (IOException e) {
            throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
        }
    }
}
