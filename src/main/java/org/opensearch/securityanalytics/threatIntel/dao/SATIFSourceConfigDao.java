/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.dao;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigResponse;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.threadpool.ThreadPool;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

/**
 * CRUD for threat intel feeds source config object
 */
public class SATIFSourceConfigDao {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigDao.class);
    private final Client client;
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;
    private final ThreadPool threadPool;


    public SATIFSourceConfigDao(final Client client, final ClusterService clusterService, ThreadPool threadPool) {
        this.client = client;
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
        this.threadPool = threadPool;
    }

    public void indexTIFSourceConfig(SATIFSourceConfig satifSourceConfig,
                                     TimeValue indexTimeout,
                                     WriteRequest.RefreshPolicy refreshPolicy,
                                     final ActionListener<SATIFSourceConfig> actionListener) throws Exception {
        IndexRequest indexRequest = new IndexRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                .setRefreshPolicy(refreshPolicy)
                .source(satifSourceConfig.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                .timeout(indexTimeout);
        log.debug("Indexing tif source config");
        client.index(indexRequest, new ActionListener<>() {
            @Override
            public void onResponse(IndexResponse response) {
                log.debug("TIF source config indexed success.");
                satifSourceConfig.setId(response.getId());
                actionListener.onResponse(satifSourceConfig);
            }
            @Override
            public void onFailure(Exception e) {
                throw new SecurityAnalyticsException("Exception saving the tif source config in index", RestStatus.INTERNAL_SERVER_ERROR, e);
            }
        });
    }

    public ThreadPool getThreadPool() {
        return threadPool;
    }


    // Get the job config index mapping
    private String getIndexMapping() {
        try {
            try (InputStream is = SATIFSourceConfigDao.class.getResourceAsStream("/mappings/threat_intel_job_mapping.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Runtime exception when getting the threat intel index mapping", e);
            throw new SecurityAnalyticsException("Runtime exception when getting the threat intel index mapping", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }

    // Create Threat intel config index
    /**
     * Index name: .opensearch-sap--job
     * Mapping: /mappings/threat_intel_job_mapping.json
     *
     * @param stepListener setup listener
     */
    public void createJobIndexIfNotExists(final StepListener<Void> stepListener) {
        // check if job index exists
        if (clusterService.state().metadata().hasIndex(SecurityAnalyticsPlugin.JOB_INDEX_NAME) == true) {
            stepListener.onResponse(null);
            return;
        }
        final CreateIndexRequest createIndexRequest = new CreateIndexRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME).mapping(getIndexMapping())
                .settings(SecurityAnalyticsPlugin.TIF_JOB_INDEX_SETTING);
        StashedThreadContext.run(client, () -> client.admin().indices().create(createIndexRequest, new ActionListener<>() {
            @Override
            public void onResponse(final CreateIndexResponse createIndexResponse) {
                log.debug("Job index created");
                stepListener.onResponse(null);
            }

            @Override
            public void onFailure(final Exception e) {
                if (e instanceof ResourceAlreadyExistsException) {
                    log.info("index[{}] already exist", SecurityAnalyticsPlugin.JOB_INDEX_NAME);
                    stepListener.onResponse(null);
                    return;
                }
                log.error("Failed to create security analytics threat intel job index", e);
                stepListener.onFailure(e);
            }
        }));
    }

    // Common utils interface class
    IndexTIFSourceConfigResponse indexTIFConfig(SAIndexTIFSourceConfigRequest request, ActionListener <SAIndexTIFSourceConfigRequest> listener) {
        return null;
    }

}
