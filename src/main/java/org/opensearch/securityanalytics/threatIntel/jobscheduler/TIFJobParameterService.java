/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

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
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

/**
 * Data access object for tif job
 */
public class TIFJobParameterService {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private static final Integer MAX_SIZE = 1000;
    private final Client client;
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;

    public TIFJobParameterService(final Client client, final ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
    }

    /**
     * Create tif job index
     *
     * @param stepListener setup listener
     */
    public void createIndexIfNotExists(final StepListener<Void> stepListener) {
        if (clusterService.state().metadata().hasIndex(TIFJobExtension.JOB_INDEX_NAME) == true) {
            stepListener.onResponse(null);
            return;
        }
        final CreateIndexRequest createIndexRequest = new CreateIndexRequest(TIFJobExtension.JOB_INDEX_NAME).mapping(getIndexMapping())
                .settings(TIFJobExtension.INDEX_SETTING);
        StashedThreadContext.run(client, () -> client.admin().indices().create(createIndexRequest, new ActionListener<>() {
            @Override
            public void onResponse(final CreateIndexResponse createIndexResponse) {
                stepListener.onResponse(null);
            }

            @Override
            public void onFailure(final Exception e) {
                if (e instanceof ResourceAlreadyExistsException) {
                    log.info("index[{}] already exist", TIFJobExtension.JOB_INDEX_NAME);
                    stepListener.onResponse(null);
                    return;
                }
                stepListener.onFailure(e);
            }
        }));
    }

    private String getIndexMapping() {
        try {
            try (InputStream is = TIFJobParameterService.class.getResourceAsStream("/mappings/threat_intel_job_mapping.json")) {
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
     * Update jobSchedulerParameter in an index {@code TIFJobExtension.JOB_INDEX_NAME}
     * @param jobSchedulerParameter the jobSchedulerParameter
     * @return index response
     */
    public IndexResponse updateJobSchedulerParameter(final TIFJobParameter jobSchedulerParameter) {
        jobSchedulerParameter.setLastUpdateTime(Instant.now());
        return StashedThreadContext.run(client, () -> {
            try {
                return client.prepareIndex(TIFJobExtension.JOB_INDEX_NAME)
                        .setId(jobSchedulerParameter.getName())
                        .setOpType(DocWriteRequest.OpType.INDEX)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .setSource(jobSchedulerParameter.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                        .execute()
                        .actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT));
            } catch (IOException e) {
                throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
            }
        });
    }

    /**
     * Update tif jobs in an index {@code TIFJobExtension.JOB_INDEX_NAME}
     * @param tifJobParameters the tifJobParameters
     * @param listener action listener
     */
    public void updateJobSchedulerParameter(final List<TIFJobParameter> tifJobParameters, final ActionListener<BulkResponse> listener) {
        BulkRequest bulkRequest = new BulkRequest();
        tifJobParameters.stream().map(tifJobParameter -> {
            tifJobParameter.setLastUpdateTime(Instant.now());
            return tifJobParameter;
        }).map(this::toIndexRequest).forEach(indexRequest -> bulkRequest.add(indexRequest));
        StashedThreadContext.run(client, () -> client.bulk(bulkRequest, listener));
    }
    private IndexRequest toIndexRequest(TIFJobParameter tifJobParameter) {
        try {
            IndexRequest indexRequest = new IndexRequest();
            indexRequest.index(TIFJobExtension.JOB_INDEX_NAME);
            indexRequest.id(tifJobParameter.getName());
            indexRequest.opType(DocWriteRequest.OpType.INDEX);
            indexRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
            indexRequest.source(tifJobParameter.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            return indexRequest;
        } catch (IOException e) {
            throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
        }
    }

    /**
     * Get tif job from an index {@code TIFJobExtension.JOB_INDEX_NAME}
     * @param name the name of a tif job
     * @return tif job
     * @throws IOException exception
     */
    public TIFJobParameter getJobParameter(final String name) throws IOException {
        GetRequest request = new GetRequest(TIFJobExtension.JOB_INDEX_NAME, name);
        GetResponse response;
        try {
            response = StashedThreadContext.run(client, () -> client.get(request).actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT)));
            if (response.isExists() == false) {
                log.error("TIF job[{}] does not exist in an index[{}]", name, TIFJobExtension.JOB_INDEX_NAME);
                return null;
            }
        } catch (IndexNotFoundException e) {
            log.error("Index[{}] is not found", TIFJobExtension.JOB_INDEX_NAME);
            return null;
        }

        XContentParser parser = XContentHelper.createParser(
                NamedXContentRegistry.EMPTY,
                LoggingDeprecationHandler.INSTANCE,
                response.getSourceAsBytesRef()
        );
        return TIFJobParameter.PARSER.parse(parser, null);
    }

    /**
     * Put tifJobParameter in an index {@code TIFJobExtension.JOB_INDEX_NAME}
     *
     * @param tifJobParameter the tifJobParameter
     * @param listener the listener
     */
    public void putTIFJobParameter(final TIFJobParameter tifJobParameter, final ActionListener listener) {
        tifJobParameter.setLastUpdateTime(Instant.now());
        StashedThreadContext.run(client, () -> {
            try {
                client.prepareIndex(TIFJobExtension.JOB_INDEX_NAME)
                        .setId(tifJobParameter.getName())
                        .setOpType(DocWriteRequest.OpType.CREATE)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .setSource(tifJobParameter.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                        .execute(listener);
            } catch (IOException e) {
                throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
            }
        });
    }

    /**
     * Delete tifJobParameter in an index {@code TIFJobExtension.JOB_INDEX_NAME}
     *
     * @param tifJobParameter the tifJobParameter
     *
     */
    public void deleteTIFJobParameter(final TIFJobParameter tifJobParameter) {
        DeleteResponse response = client.prepareDelete()
                .setIndex(TIFJobExtension.JOB_INDEX_NAME)
                .setId(tifJobParameter.getName())
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .execute()
                .actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT));

        if (response.status().equals(RestStatus.OK)) {
            log.info("deleted tifJobParameter[{}] successfully", tifJobParameter.getName());
        } else if (response.status().equals(RestStatus.NOT_FOUND)) {
            throw new ResourceNotFoundException("tifJobParameter[{}] does not exist", tifJobParameter.getName());
        } else {
            throw new OpenSearchException("failed to delete tifJobParameter[{}] with status[{}]", tifJobParameter.getName(), response.status());
        }
    }

    /**
     * Get tif job from an index {@code TIFJobExtension.JOB_INDEX_NAME}
     * @param name the name of a tif job
     * @param actionListener the action listener
     */
    public void getJobParameter(final String name, final ActionListener<TIFJobParameter> actionListener) {
        GetRequest request = new GetRequest(TIFJobExtension.JOB_INDEX_NAME, name);
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
                    actionListener.onResponse(TIFJobParameter.PARSER.parse(parser, null));
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
     * Get tif jobs from an index {@code TIFJobExtension.JOB_INDEX_NAME}
     * @param names the array of tif job names
     * @param actionListener the action listener
     */
    public void getTIFJobParameters(final String[] names, final ActionListener<List<TIFJobParameter>> actionListener) {
        StashedThreadContext.run(
                client,
                () -> client.prepareMultiGet()
                        .add(TIFJobExtension.JOB_INDEX_NAME, names)
                        .execute(createGetTIFJobParameterQueryActionLister(MultiGetResponse.class, actionListener))
        );
    }

    /**
     * Get all tif jobs up to {@code MAX_SIZE} from an index {@code TIFJobExtension.JOB_INDEX_NAME}
     * @param actionListener the action listener
     */
    public void getAllTIFJobParameters(final ActionListener<List<TIFJobParameter>> actionListener) {
        StashedThreadContext.run(
                client,
                () -> client.prepareSearch(TIFJobExtension.JOB_INDEX_NAME)
                        .setQuery(QueryBuilders.matchAllQuery())
                        .setPreference(Preference.PRIMARY.type())
                        .setSize(MAX_SIZE)
                        .execute(createGetTIFJobParameterQueryActionLister(SearchResponse.class, actionListener))
        );
    }

    /**
     * Get all tif jobs up to {@code MAX_SIZE} from an index {@code TIFJobExtension.JOB_INDEX_NAME}
     */
    public List<TIFJobParameter> getAllTIFJobParameters() {
        SearchResponse response = StashedThreadContext.run(
                client,
                () -> client.prepareSearch(TIFJobExtension.JOB_INDEX_NAME)
                        .setQuery(QueryBuilders.matchAllQuery())
                        .setPreference(Preference.PRIMARY.type())
                        .setSize(MAX_SIZE)
                        .execute()
                        .actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT))
        );

        List<BytesReference> bytesReferences = toBytesReferences(response);
        return bytesReferences.stream().map(bytesRef -> toTIFJobParameter(bytesRef)).collect(Collectors.toList());
    }

    private <T> ActionListener<T> createGetTIFJobParameterQueryActionLister(
            final Class<T> response,
            final ActionListener<List<TIFJobParameter>> actionListener
    ) {
        return new ActionListener<T>() {
            @Override
            public void onResponse(final T response) {
                try {
                    List<BytesReference> bytesReferences = toBytesReferences(response);
                    List<TIFJobParameter> tifJobParameters = bytesReferences.stream()
                            .map(bytesRef -> toTIFJobParameter(bytesRef))
                            .collect(Collectors.toList());
                    actionListener.onResponse(tifJobParameters);
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

    private TIFJobParameter toTIFJobParameter(final BytesReference bytesReference) {
        try {
            XContentParser parser = XContentHelper.createParser(
                    NamedXContentRegistry.EMPTY,
                    LoggingDeprecationHandler.INSTANCE,
                    bytesReference
            );
            return TIFJobParameter.PARSER.parse(parser, null);
        } catch (IOException e) {
            throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e); //TODO
        }
    }
}
