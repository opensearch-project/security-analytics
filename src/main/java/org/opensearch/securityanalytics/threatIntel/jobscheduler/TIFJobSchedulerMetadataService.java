/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.action.ThreatIntelIndicesResponse;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.stream.Collectors;

/**
 * Service to handle CRUD operations for threat intel feeds job scheduler metadata
 */
public class TIFJobSchedulerMetadataService {
    private static final Logger log = LogManager.getLogger(TIFJobSchedulerMetadataService.class);
    private final Client client;
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;

    public TIFJobSchedulerMetadataService(final Client client, final ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
    }

    /**
     * Create tif job index
     *
     * @param stepListener setup listener
     */
    public void createJobIndexIfNotExists(final StepListener<Void> stepListener) {
        if (clusterService.state().metadata().hasIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME) == true) {
            stepListener.onResponse(null);
            return;
        }
        final CreateIndexRequest createIndexRequest = new CreateIndexRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME).mapping(getIndexMapping())
                .settings(SecurityAnalyticsPlugin.TIF_JOB_INDEX_SETTING);
        StashedThreadContext.run(client, () -> client.admin().indices().create(createIndexRequest, new ActionListener<>() {
            @Override
            public void onResponse(final CreateIndexResponse createIndexResponse) {
                stepListener.onResponse(null);
            }

            @Override
            public void onFailure(final Exception e) {
                if (e instanceof ResourceAlreadyExistsException) {
                    log.info("index[{}] already exist", SecurityAnalyticsPlugin.JOB_INDEX_NAME);
                    stepListener.onResponse(null);
                    return;
                }
                stepListener.onFailure(e);
            }
        }));
    }

    private String getIndexMapping() {
        try {
            try (InputStream is = TIFJobSchedulerMetadataService.class.getResourceAsStream("/mappings/threat_intel_job_mapping.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Runtime exception", e);
            throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }

    /**
     * Update jobSchedulerParameter in an index {@code TIFJobExtension.JOB_INDEX_NAME}
     * @param jobSchedulerParameter the jobSchedulerParameter
     */
    public void updateJobSchedulerMetadata(final TIFJobSchedulerMetadata jobSchedulerParameter, final ActionListener<ThreatIntelIndicesResponse> listener) {
        jobSchedulerParameter.setLastUpdateTime(Instant.now());
        StashedThreadContext.run(client, () -> {
            try {
                if (listener != null) {
                    client.prepareIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                            .setId(jobSchedulerParameter.getName())
                            .setOpType(DocWriteRequest.OpType.INDEX)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                            .setSource(jobSchedulerParameter.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                            .execute(new ActionListener<>() {
                                @Override
                                public void onResponse(IndexResponse indexResponse) {
                                    if (indexResponse.status().getStatus() >= 200 && indexResponse.status().getStatus() < 300) {
                                        listener.onResponse(new ThreatIntelIndicesResponse(true, jobSchedulerParameter.getIndices()));
                                    } else {
                                        listener.onFailure(new OpenSearchStatusException("update of job scheduler parameter failed", RestStatus.INTERNAL_SERVER_ERROR));
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    listener.onFailure(e);
                                }
                            });
                } else {
                    client.prepareIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                            .setId(jobSchedulerParameter.getName())
                            .setOpType(DocWriteRequest.OpType.INDEX)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                            .setSource(jobSchedulerParameter.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                            .execute().actionGet();
                }
            } catch (IOException e) {
                throw new SecurityAnalyticsException("Runtime exception", RestStatus.INTERNAL_SERVER_ERROR, e);
            }
        });
    }

    /**
     * Get tif job from an index {@code TIFJobExtension.JOB_INDEX_NAME}
     * @param name the name of a tif job
     * @return tif job
     * @throws IOException exception
     */
    public TIFJobSchedulerMetadata getJobSchedulerMetadata(final String name) throws IOException {
        GetRequest request = new GetRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME, name);
        GetResponse response;
        try {
            response = StashedThreadContext.run(client, () -> client.get(request).actionGet(clusterSettings.get(SecurityAnalyticsSettings.THREAT_INTEL_TIMEOUT)));
            if (response.isExists() == false) {
                log.error("TIF job[{}] does not exist in an index[{}]", name, SecurityAnalyticsPlugin.JOB_INDEX_NAME);
                return null;
            }
        } catch (IndexNotFoundException e) {
            log.error("Index[{}] is not found", SecurityAnalyticsPlugin.JOB_INDEX_NAME);
            return null;
        }

        XContentParser parser = XContentHelper.createParser(
                NamedXContentRegistry.EMPTY,
                LoggingDeprecationHandler.INSTANCE,
                response.getSourceAsBytesRef()
        );
        return TIFJobSchedulerMetadata.PARSER.parse(parser, null);
    }

    /**
     * Put tifJobSchedulerMetadata in an index {@code TIFJobExtension.JOB_INDEX_NAME}
     *
     * @param tifJobSchedulerMetadata the tifJobSchedulerMetadata
     * @param listener the listener
     */
    public void saveTIFJobSchedulerMetadata(final TIFJobSchedulerMetadata tifJobSchedulerMetadata, final ActionListener listener) {
        tifJobSchedulerMetadata.setLastUpdateTime(Instant.now());
        StashedThreadContext.run(client, () -> {
            try {
                client.prepareIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                        .setId(tifJobSchedulerMetadata.getName())
                        .setOpType(DocWriteRequest.OpType.CREATE)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .setSource(tifJobSchedulerMetadata.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                        .execute(listener);
            } catch (IOException e) {
                throw new SecurityAnalyticsException("Exception saving the threat intel feed job parameter in index", RestStatus.INTERNAL_SERVER_ERROR, e);
            }
        });
    }
}
