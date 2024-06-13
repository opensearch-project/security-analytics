/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.routing.Preference;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.jobscheduler.spi.LockModel;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.fetch.subphase.FetchSourceContext;
import org.opensearch.securityanalytics.SecurityAnalyticsPlugin;
import org.opensearch.securityanalytics.threatIntel.action.monitor.SearchThreatIntelMonitorAction;
import org.opensearch.securityanalytics.threatIntel.action.monitor.request.SearchThreatIntelMonitorRequest;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.threatIntel.common.TIFLockService;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.threadpool.ThreadPool;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.stream.Collectors;

import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.INDEX_TIMEOUT;
import static org.opensearch.securityanalytics.transport.TransportIndexDetectorAction.PLUGIN_OWNER_FIELD;

/**
 * CRUD for threat intel feeds source config object
 */
public class SATIFSourceConfigService {
    private static final Logger log = LogManager.getLogger(SATIFSourceConfigService.class);
    private final Client client;
    private final ClusterService clusterService;
    private final ClusterSettings clusterSettings;
    private final ThreadPool threadPool;
    private final NamedXContentRegistry xContentRegistry;
    private final TIFLockService lockService;


    public SATIFSourceConfigService(final Client client,
                                    final ClusterService clusterService,
                                    ThreadPool threadPool,
                                    NamedXContentRegistry xContentRegistry,
                                    final TIFLockService lockService
    ) {
        this.client = client;
        this.clusterService = clusterService;
        this.clusterSettings = clusterService.getClusterSettings();
        this.threadPool = threadPool;
        this.xContentRegistry = xContentRegistry;
        this.lockService = lockService;
    }

    public void indexTIFSourceConfig(SATIFSourceConfig SaTifSourceConfig,
                                     final LockModel lock,
                                     final ActionListener<SATIFSourceConfig> actionListener
    ) {
        StepListener<Void> createIndexStepListener = new StepListener<>();
        createIndexStepListener.whenComplete(v -> {
            try {
                IndexRequest indexRequest = new IndexRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                        .source(SaTifSourceConfig.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                        .timeout(clusterSettings.get(INDEX_TIMEOUT));

                log.debug("Indexing tif source config");
                client.index(indexRequest, ActionListener.wrap(
                        response -> {
                            log.debug("Threat intel source config with id [{}] indexed success.", response.getId());
                            SATIFSourceConfig responseSaTifSourceConfig = createSATIFSourceConfig(SaTifSourceConfig, response);
                            actionListener.onResponse(responseSaTifSourceConfig);
                        }, e -> {
                            log.error("Failed to index threat intel source config with id [{}]", SaTifSourceConfig.getId());
                            actionListener.onFailure(e);
                        })
                );

            } catch (IOException e) {
                log.error("Exception saving the threat intel source config in index", e);
                actionListener.onFailure(e);
            }
        }, exception -> {
            lockService.releaseLock(lock);
            log.error("Failed to release lock", exception);
            actionListener.onFailure(exception);
        });
        createJobIndexIfNotExists(createIndexStepListener);
    }

    private static SATIFSourceConfig createSATIFSourceConfig(SATIFSourceConfig SaTifSourceConfig, IndexResponse response) {
        return new SATIFSourceConfig(
                response.getId(),
                response.getVersion(),
                SaTifSourceConfig.getName(),
                SaTifSourceConfig.getFeedFormat(),
                SaTifSourceConfig.getFeedType(),
                SaTifSourceConfig.getDescription(),
                SaTifSourceConfig.getCreatedByUser(),
                SaTifSourceConfig.getCreatedAt(),
                SaTifSourceConfig.getSource(),
                SaTifSourceConfig.getEnabledTime(),
                SaTifSourceConfig.getLastUpdateTime(),
                SaTifSourceConfig.getSchedule(),
                SaTifSourceConfig.getState(),
                SaTifSourceConfig.getRefreshType(),
                SaTifSourceConfig.getLastRefreshedTime(),
                SaTifSourceConfig.getLastRefreshedUser(),
                SaTifSourceConfig.isEnabled(),
                SaTifSourceConfig.getIocStoreConfig(),
                SaTifSourceConfig.getIocTypes()
        );
    }

    // Get the job config index mapping
    private String getIndexMapping() {
        try {
            try (InputStream is = SATIFSourceConfigService.class.getResourceAsStream("/mappings/threat_intel_job_mapping.json")) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().map(String::trim).collect(Collectors.joining());
                }
            }
        } catch (IOException e) {
            log.error("Failed to get the threat intel index mapping", e);
            throw new SecurityAnalyticsException("Failed to get threat intel index mapping", RestStatus.INTERNAL_SERVER_ERROR, e);
        }
    }

    // Create TIF source config index

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
        StashedThreadContext.run(client, () -> client.admin().indices().create(createIndexRequest, ActionListener.wrap(
                r -> {
                    log.debug("[{}] index created", SecurityAnalyticsPlugin.JOB_INDEX_NAME);
                    stepListener.onResponse(null);
                }, e -> {
                    if (e instanceof ResourceAlreadyExistsException) {
                        log.info("Index [{}] already exists", SecurityAnalyticsPlugin.JOB_INDEX_NAME);
                        stepListener.onResponse(null);
                        return;
                    }
                    log.error("Failed to create [{}] index", SecurityAnalyticsPlugin.JOB_INDEX_NAME, e);
                    stepListener.onFailure(e);
                }
        )));
    }


    // Get TIF source config
    public void getTIFSourceConfig(
            String tifSourceConfigId,
            ActionListener<SATIFSourceConfig> actionListener
    ) {
        GetRequest getRequest = new GetRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME, tifSourceConfigId);
        client.get(getRequest, ActionListener.wrap(
                getResponse -> {
                    if (!getResponse.isExists()) {
                        actionListener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException("Threat intel source config not found.", RestStatus.NOT_FOUND)));
                        return;
                    }
                    SATIFSourceConfig SaTifSourceConfig = null;
                    if (!getResponse.isSourceEmpty()) {
                        XContentParser xcp = XContentHelper.createParser(
                                xContentRegistry, LoggingDeprecationHandler.INSTANCE,
                                getResponse.getSourceAsBytesRef(), XContentType.JSON
                        );
                        SaTifSourceConfig = SATIFSourceConfig.docParse(xcp, getResponse.getId(), getResponse.getVersion());
                        assert SaTifSourceConfig != null;
                    }
                    log.debug("Threat intel source config with id [{}] fetched", getResponse.getId());
                    actionListener.onResponse(SaTifSourceConfig);
                }, e -> {
                    log.error("Failed to fetch threat intel source config document", e);
                    actionListener.onFailure(e);
                })
        );
    }

    public void searchTIFSourceConfigs(
            final SearchRequest searchRequest,
            final ActionListener<SearchResponse> actionListener
    ) {
        try {
            client.search(searchRequest, ActionListener.wrap(
                    searchResponse -> {
                        if (searchResponse.isTimedOut()) {
                            actionListener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException("Search threat intel source configs request timed out", RestStatus.REQUEST_TIMEOUT)));
                            return;
                        }

                        log.debug("Fetched all threat intel source configs successfully.");
                        actionListener.onResponse(searchResponse);
                    }, e -> {
                        log.error("Failed to fetch all threat intel source configs for search request [{}]", searchRequest, e);
                        actionListener.onFailure(e);
                    })
            );
        } catch (Exception e) {
            log.error("Failed to fetch all threat intel source configs for search request [{}]", searchRequest, e);
            actionListener.onFailure(e);
        }
    }


    // Update TIF source config
    public void updateTIFSourceConfig(
            SATIFSourceConfig SaTifSourceConfig,
            final ActionListener<IndexResponse> actionListener
    ) {
        try {
            IndexRequest indexRequest = new IndexRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .source(SaTifSourceConfig.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                    .id(SaTifSourceConfig.getId())
                    .timeout(clusterSettings.get(INDEX_TIMEOUT));

            client.index(indexRequest, ActionListener.wrap(response -> {
                        log.debug("Threat intel source config with id [{}] update success.", response.getId());
                        actionListener.onResponse(response);
                    }, e -> {
                        log.error("Failed to update threat intel source config with id [{}]", SaTifSourceConfig.getId());
                        actionListener.onFailure(e);
                    }
            ));
        } catch (IOException e) {
            log.error("Exception updating the threat intel source config in index", e);
        }
    }

    // Delete TIF source config
    public void deleteTIFSourceConfig(
            SATIFSourceConfig SaTifSourceConfig,
            final ActionListener<DeleteResponse> actionListener
    ) {
        DeleteRequest request = new DeleteRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME, SaTifSourceConfig.getId())
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .timeout(clusterSettings.get(INDEX_TIMEOUT));

        client.delete(request, ActionListener.wrap(
                deleteResponse -> {
                    if (deleteResponse.status().equals(RestStatus.OK)) {
                        log.debug("Deleted threat intel source config [{}] successfully", SaTifSourceConfig.getId());
                        actionListener.onResponse(deleteResponse);
                    } else if (deleteResponse.status().equals(RestStatus.NOT_FOUND)) {
                        throw SecurityAnalyticsException.wrap(new OpenSearchStatusException(String.format(Locale.getDefault(), "Threat intel source config with id [{%s}] not found", SaTifSourceConfig.getId()), RestStatus.NOT_FOUND));
                    } else {
                        throw SecurityAnalyticsException.wrap(new OpenSearchStatusException(String.format(Locale.getDefault(), "Failed to delete threat intel source config [{%s}]", SaTifSourceConfig.getId()), deleteResponse.status()));
                    }
                }, e -> {
                    log.error("Failed to delete threat intel source config with id [{}]", SaTifSourceConfig.getId());
                    actionListener.onFailure(e);
                }
        ));
    }

    public void checkAndEnsureThreatIntelMonitorsDeleted(
            ActionListener<Boolean> listener
    ) {
        // TODO: change this to use search source configs API call
        SearchRequest searchRequest = new SearchRequest(SecurityAnalyticsPlugin.JOB_INDEX_NAME)
                .source(new SearchSourceBuilder()
                        .seqNoAndPrimaryTerm(false)
                        .version(false)
                        .query(QueryBuilders.matchAllQuery())
                        .fetchSource(FetchSourceContext.FETCH_SOURCE)
                ).preference(Preference.PRIMARY_FIRST.type());

        // Search if there is only one threat intel source config left
        client.search(searchRequest, ActionListener.wrap(
                saTifSourceConfigResponse -> {
                    if (saTifSourceConfigResponse.getHits().getHits().length <= 1) {
                        String alertingConfigIndex = ".opendistro-alerting-config";
                        if (clusterService.state().metadata().hasIndex(alertingConfigIndex) == false) {
                            log.debug("[{}] index does not exist, continuing deleting threat intel source config", alertingConfigIndex);
                            listener.onResponse(true);
                        } else {
                            // Search alerting config index for at least one threat intel monitor
                            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                                    .seqNoAndPrimaryTerm(false)
                                    .version(false)
                                    .query(QueryBuilders.matchAllQuery())
                                    .fetchSource(FetchSourceContext.FETCH_SOURCE);

                            SearchRequest newSearchRequest = new SearchRequest();
                            newSearchRequest.source(searchSourceBuilder);
                            newSearchRequest.indices(alertingConfigIndex);
                            newSearchRequest.preference(Preference.PRIMARY_FIRST.type());

                            BoolQueryBuilder boolQueryBuilder = QueryBuilders.boolQuery().must(newSearchRequest.source().query());
                            BoolQueryBuilder bqb = new BoolQueryBuilder();
                            bqb.should().add(new BoolQueryBuilder().must(QueryBuilders.matchQuery("monitor.owner", PLUGIN_OWNER_FIELD)));
                            boolQueryBuilder.filter(bqb);
                            newSearchRequest.source().query(boolQueryBuilder); // remove this once logic is moved to transport layer

                            client.execute(SearchThreatIntelMonitorAction.INSTANCE, new SearchThreatIntelMonitorRequest(newSearchRequest), ActionListener.wrap(
                                    response -> {
                                        if (response.getHits().getHits().length == 0) {
                                            log.debug("All threat intel monitors are deleted, continuing deleting threat intel source config");
                                            listener.onResponse(true);
                                        } else {
                                            log.error("All threat intel monitors need to be deleted before deleting threat intel source config");
                                            listener.onResponse(false);
                                        }
                                    }, e -> {
                                        log.error("Failed to search for threat intel monitors");
                                        listener.onFailure(e);
                                    }
                            ));
                        }
                    } else {
                        // If there are multiple threat intel source configs left, proceed with deletion
                        log.debug("Multiple threat intel source configs exist, threat intel monitors do not need to be deleted");
                        listener.onResponse(true);
                    }
                }, e -> {
                    log.error("Failed to search for threat intel source configs");
                    listener.onFailure(e);
                }
        ));

    }

}
