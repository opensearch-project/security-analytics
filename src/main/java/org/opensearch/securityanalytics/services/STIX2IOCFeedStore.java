/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.rollover.RolloverRequest;
import org.opensearch.action.admin.indices.rollover.RolloverResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.io.Streams;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.securityanalytics.commons.model.IOC;
import org.opensearch.securityanalytics.commons.model.UpdateAction;
import org.opensearch.securityanalytics.commons.store.FeedStore;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.threatIntel.model.DefaultIocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.securityanalytics.util.IndexUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

public class STIX2IOCFeedStore implements FeedStore {
    public static final String IOC_INDEX_NAME_BASE = ".opensearch-sap-iocs";
    public static final String IOC_ALL_INDEX_PATTERN = IOC_INDEX_NAME_BASE + "-*";
    public static final String IOC_FEED_ID_PLACEHOLDER = "FEED_ID";
    public static final String IOC_INDEX_NAME_TEMPLATE = IOC_INDEX_NAME_BASE + "-" + IOC_FEED_ID_PLACEHOLDER;
    public static final String IOC_WRITE_INDEX_ALIAS = IOC_INDEX_NAME_TEMPLATE;
    public static final String IOC_TIME_PLACEHOLDER = "TIME";
    public static final String IOC_INDEX_PATTERN = IOC_INDEX_NAME_TEMPLATE + "-" + IOC_TIME_PLACEHOLDER;

    private final Logger log = LogManager.getLogger(STIX2IOCFeedStore.class);
    Instant startTime = Instant.now();

    private Client client;
    private ClusterService clusterService;
    private SATIFSourceConfig saTifSourceConfig;

    // TODO hurneyt FetchIocsActionResponse is just a placeholder response type for now
    private ActionListener<STIX2IOCFetchService.STIX2IOCFetchResponse> baseListener;

    // TODO hurneyt this is using TIF batch size setting. Consider adding IOC-specific setting
    private Integer batchSize;

    public STIX2IOCFeedStore(
            Client client,
            ClusterService clusterService,
            SATIFSourceConfig saTifSourceConfig,
            ActionListener<STIX2IOCFetchService.STIX2IOCFetchResponse> listener) {
        super();
        this.client = client;
        this.clusterService = clusterService;
        this.saTifSourceConfig = saTifSourceConfig;
        this.baseListener = listener;
        batchSize = clusterService.getClusterSettings().get(SecurityAnalyticsSettings.BATCH_SIZE);
    }

    @Override
    public void storeIOCs(Map<IOC, UpdateAction> actionToIOCs) {
        Map<UpdateAction, List<STIX2IOC>> iocsSortedByAction = new HashMap<>();
        actionToIOCs.forEach((key, value) -> {
            if (key.getClass() != STIX2IOC.class) {
                throw new IllegalArgumentException("Only supports STIX2-formatted IOCs.");
            } else {
                iocsSortedByAction.putIfAbsent(value, new ArrayList<>());
                iocsSortedByAction.get(value).add((STIX2IOC) key);
            }
        });

        for (Map.Entry<UpdateAction, List<STIX2IOC>> entry : iocsSortedByAction.entrySet()) {
            switch (entry.getKey()) {
                case DELETE:
                    // TODO hurneyt consider whether DELETE actions should be handled elsewhere
                    break;
                case UPSERT:
                    try {
                        indexIocs(entry.getValue());
                    } catch (IOException e) {
                        baseListener.onFailure(new RuntimeException(e));
                    }
                    break;
                default:
                    baseListener.onFailure(new IllegalArgumentException("Unsupported action."));
            }
        }
    }

    public void indexIocs(List<STIX2IOC> iocs) throws IOException {
        String iocAlias = getIocIndexAlias(saTifSourceConfig.getId());
        String iocPattern = getIocIndexRolloverPattern(saTifSourceConfig.getId());

        if (iocIndexExists(iocAlias) == false) {
            initFeedIndex(iocAlias, iocPattern, ActionListener.wrap(
                    r -> {
                        saTifSourceConfig.getIocTypes().forEach(type -> {
                            String writeIndex = IndexUtils.getWriteIndex(iocAlias, clusterService.state());
                            String lowerCaseType = type.toLowerCase(Locale.ROOT);
                            ((DefaultIocStoreConfig) saTifSourceConfig.getIocStoreConfig()).getIocMapStore().putIfAbsent(lowerCaseType, new ArrayList<>());
                            ((DefaultIocStoreConfig) saTifSourceConfig.getIocStoreConfig()).getIocMapStore().get(lowerCaseType).add(iocAlias);
                            ((DefaultIocStoreConfig) saTifSourceConfig.getIocStoreConfig()).getIocMapStore().get(lowerCaseType).add(writeIndex);
                        });
                        bulkIndexIocs(iocs, iocAlias);
                    }, e-> {
                        log.error("Failed to initialize the IOC index and save the IOCs", e);
                        baseListener.onFailure(e);
                    }
            ));
        } else {
            rolloverIndex(iocAlias, iocPattern, ActionListener.wrap(
                    r -> {
                        saTifSourceConfig.getIocTypes().forEach(type -> {
                            String writeIndex = IndexUtils.getWriteIndex(iocAlias, clusterService.state());
                            String lowerCaseType = type.toLowerCase(Locale.ROOT);
                            ((DefaultIocStoreConfig) saTifSourceConfig.getIocStoreConfig()).getIocMapStore().get(lowerCaseType).add(writeIndex);
                        });
                        bulkIndexIocs(iocs, iocAlias);
                    }, e -> {
                        log.error("Failed to rollover the IOC index and save the IOCs", e);
                        baseListener.onFailure(e);
                    }
            ));
        }
    }

    private void rolloverIndex(
            String alias,
            String pattern,
            ActionListener<RolloverResponse> listener
    ) {
        if (clusterService.state().metadata().hasAlias(alias) == false) {
            listener.onFailure(new OpenSearchException("Alias not initialized"));
            return;
        }

        RolloverRequest request = new RolloverRequest(alias, pattern);
        request.getCreateIndexRequest()
                .mapping(iocIndexMapping())
                .settings(Settings.builder().put("index.hidden", true).build());
        client.admin().indices().rolloverIndex(
                request,
                ActionListener.wrap(
                        rolloverResponse -> {
                            if (false == rolloverResponse.isRolledOver()) {
                                log.info(alias + "not rolled over. Rollover condition status: " + rolloverResponse.getConditionStatus());
                                listener.onFailure(new OpenSearchException(alias + "not rolled over. Rollover condition status: " + rolloverResponse.getConditionStatus()));
                            } else {
                                listener.onResponse(rolloverResponse);
                            }
                        }, e -> {
                            log.error("rollover failed for alias [" + alias + "].");
                            listener.onFailure(e);
                        }
                )
        );
    }

    private void bulkIndexIocs(List<STIX2IOC> iocs, String iocAlias) throws IOException {
        List<BulkRequest> bulkRequestList = new ArrayList<>();
        BulkRequest bulkRequest = new BulkRequest();

        for (STIX2IOC ioc : iocs) {
            IndexRequest indexRequest = new IndexRequest(iocAlias)
                    .id(StringUtils.isBlank(ioc.getId())? UUID.randomUUID().toString() : ioc.getId())
                    .opType(DocWriteRequest.OpType.INDEX)
                    .source(ioc.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            bulkRequest.add(indexRequest);

            if (bulkRequest.requests().size() == batchSize) {
                bulkRequestList.add(bulkRequest);
                bulkRequest = new BulkRequest();
            }
        }
        bulkRequest.setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        bulkRequestList.add(bulkRequest);

        GroupedActionListener<BulkResponse> bulkResponseListener = new GroupedActionListener<>(ActionListener.wrap(bulkResponses -> {
            int idx = 0;
            for (BulkResponse response : bulkResponses) {
                BulkRequest request = bulkRequestList.get(idx);
                if (response.hasFailures()) {
                    throw new OpenSearchException(
                            "Error occurred while ingesting IOCs to {} with an error {}",
                            StringUtils.join(request.getIndices()),
                            response.buildFailureMessage()
                    );
                }
                idx++;
            }
            long duration = Duration.between(startTime, Instant.now()).toMillis();
            STIX2IOCFetchService.STIX2IOCFetchResponse output = new STIX2IOCFetchService.STIX2IOCFetchResponse(iocs, duration);
            baseListener.onResponse(output);
        }, e -> {
            log.error("Failed to index IOCs for config {}", saTifSourceConfig.getId(), e);
            baseListener.onFailure(e);
        }), bulkRequestList.size());

        for (BulkRequest req : bulkRequestList) {
            try {
                StashedThreadContext.run(client, () -> client.bulk(req, bulkResponseListener));
            } catch (OpenSearchException e) {
                log.error("Failed to save IOCs for config {}", saTifSourceConfig.getId(), e);
                baseListener.onFailure(e);
            }
        }
    }

    public boolean iocIndexExists(String alias) {
        ClusterState clusterState = clusterService.state();
        return clusterState.metadata().hasAlias(alias);
    }

    public static String getIocIndexAlias(String feedSourceConfigId) {
        return IOC_WRITE_INDEX_ALIAS.replace(IOC_FEED_ID_PLACEHOLDER, feedSourceConfigId.toLowerCase(Locale.ROOT));
    }

    public static String getIocIndexRolloverPattern(String feedSourceConfigId) {
        return IOC_INDEX_PATTERN
                .replace(IOC_FEED_ID_PLACEHOLDER, feedSourceConfigId.toLowerCase(Locale.ROOT))
                .replace(IOC_TIME_PLACEHOLDER, Long.toString(Instant.now().toEpochMilli()));
    }


    public void initFeedIndex(String feedAliasName, String feedIndexName, ActionListener<CreateIndexResponse> listener) {
        var indexRequest = new CreateIndexRequest(feedIndexName)
                .mapping(iocIndexMapping())
                .settings(Settings.builder().put("index.hidden", true).build());
        indexRequest.alias(new Alias(feedAliasName)); // set the alias
        client.admin().indices().create(indexRequest, ActionListener.wrap(
                r -> {
                    log.info("Created system index {}", feedIndexName);
                    listener.onResponse(r);
                },
                e -> {
                    log.error("Failed to create system index {}", feedIndexName);
                    listener.onFailure(e);
                }
        ));
    }

    public String iocIndexMapping() {
        String iocMappingFile = "mappings/stix2_ioc_mapping.json";
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(iocMappingFile)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Streams.copy(is, out);
            return out.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load stix2_ioc_mapping.json file [" + iocMappingFile + "]", e);
        }
    }

    public SATIFSourceConfig getSaTifSourceConfig() {
        return saTifSourceConfig;
    }
}

