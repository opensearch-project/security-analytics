/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.services;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.io.Streams;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.securityanalytics.commons.model.IOC;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.commons.model.UpdateAction;
import org.opensearch.securityanalytics.commons.store.FeedStore;
import org.opensearch.securityanalytics.model.STIX2IOC;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.common.StashedThreadContext;
import org.opensearch.securityanalytics.threatIntel.model.DefaultIocStoreConfig;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfig;
import org.opensearch.transport.RemoteTransportException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.maxSystemIndexReplicas;
import static org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings.minSystemIndexReplicas;

public class STIX2IOCFeedStore implements FeedStore {
    public static final String IOC_INDEX_NAME_BASE = ".opensearch-sap-iocs";
    public static final String IOC_ALL_INDEX_PATTERN = IOC_INDEX_NAME_BASE + "-*";
    public static final String IOC_FEED_ID_PLACEHOLDER = "FEED_ID";
    public static final String IOC_INDEX_NAME_TEMPLATE = IOC_INDEX_NAME_BASE + "-" + IOC_FEED_ID_PLACEHOLDER;
    public static final String IOC_ALL_INDEX_PATTERN_BY_ID = IOC_INDEX_NAME_TEMPLATE + "-*";
    public static final String IOC_TIME_PLACEHOLDER = "TIME";
    public static final String IOC_INDEX_PATTERN = IOC_INDEX_NAME_TEMPLATE + "-" + IOC_TIME_PLACEHOLDER;

    private final Logger log = LogManager.getLogger(STIX2IOCFeedStore.class);
    private final String newActiveIndex;

    Instant startTime = Instant.now();

    private Client client;
    private ClusterService clusterService;
    private SATIFSourceConfig saTifSourceConfig;
    private ActionListener<STIX2IOCFetchService.STIX2IOCFetchResponse> baseListener;
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
        newActiveIndex = getNewActiveIndex(saTifSourceConfig.getId());
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
        StepListener<Void> initSourceConfigIndexesListener = new StepListener<>();
        initSourceConfigIndexes(initSourceConfigIndexesListener);
        initSourceConfigIndexesListener.whenComplete(r -> {
            bulkIndexIocs(iocs, newActiveIndex);
        }, e -> {
            log.error("Failed to init source config indexes");
            baseListener.onFailure(e);
        });

    }

    private void bulkIndexIocs(List<STIX2IOC> iocs, String activeIndex) throws IOException {
        if (iocs.isEmpty()) {
            long duration = Duration.between(startTime, Instant.now()).toMillis();
            STIX2IOCFetchService.STIX2IOCFetchResponse output = new STIX2IOCFetchService.STIX2IOCFetchResponse(Collections.emptyList(), duration);
            baseListener.onResponse(output);
        }

        List<BulkRequest> bulkRequestList = new ArrayList<>();
        BulkRequest bulkRequest = new BulkRequest();
        for (STIX2IOC ioc : iocs) {
            IndexRequest indexRequest = new IndexRequest(activeIndex)
                    .id(StringUtils.isBlank(ioc.getId()) ? UUID.randomUUID().toString() : ioc.getId())
                    .opType(DocWriteRequest.OpType.INDEX)
                    .source(ioc.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS));
            bulkRequest.add(indexRequest);

            if (bulkRequest.requests().size() == batchSize) {
                bulkRequestList.add(bulkRequest);
                bulkRequest = new BulkRequest();
            }
        }

        if (!bulkRequest.requests().isEmpty()) bulkRequestList.add(bulkRequest);
        if (!bulkRequestList.isEmpty()) bulkRequestList.get(bulkRequestList.size() - 1).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

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

    public static String getAllIocIndexPatternById(String sourceConfigId) {
        return IOC_ALL_INDEX_PATTERN_BY_ID.replace(IOC_FEED_ID_PLACEHOLDER, sourceConfigId.toLowerCase(Locale.ROOT));
    }

    public static String getNewActiveIndex(String sourceConfigId) {
        return IOC_INDEX_PATTERN
                .replace(IOC_FEED_ID_PLACEHOLDER, sourceConfigId.toLowerCase(Locale.ROOT))
                .replace(IOC_TIME_PLACEHOLDER, Long.toString(Instant.now().toEpochMilli()));
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

    private void initSourceConfigIndexes(StepListener<Void> stepListener) {
        String iocIndexPattern = getAllIocIndexPatternById(saTifSourceConfig.getId());
        initFeedIndex(newActiveIndex, ActionListener.wrap(
                r -> {
                    // reset the store configs
                    if (saTifSourceConfig.getIocStoreConfig() instanceof DefaultIocStoreConfig) {
                        ((DefaultIocStoreConfig) saTifSourceConfig.getIocStoreConfig()).getIocToIndexDetails().clear();
                    }

                    // recreate the store configs
                    saTifSourceConfig.getIocTypes().forEach(type -> {
                        if (saTifSourceConfig.getIocStoreConfig() instanceof DefaultIocStoreConfig) {
                            DefaultIocStoreConfig.IocToIndexDetails iocToIndexDetails =
                                    new DefaultIocStoreConfig.IocToIndexDetails(new IOCType(type), iocIndexPattern, newActiveIndex);
                            ((DefaultIocStoreConfig) saTifSourceConfig.getIocStoreConfig()).getIocToIndexDetails().add(iocToIndexDetails);
                        }
                    });
                    stepListener.onResponse(null);
                }, e-> {
                    log.error("Failed to initialize the IOC index and save the IOCs", e);
                    stepListener.onFailure(e);
                }
        ));
    }

    private void initFeedIndex(String feedIndexName, ActionListener<CreateIndexResponse> listener) {
        if (!clusterService.state().routingTable().hasIndex(newActiveIndex)) {
            var indexRequest = new CreateIndexRequest(feedIndexName)
                    .mapping(iocIndexMapping())
                    .settings(Settings.builder()
                            .put("index.hidden", true)
                            .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                            .put("index.auto_expand_replicas", minSystemIndexReplicas + "-" + maxSystemIndexReplicas)
                            .build()
                    );
            client.admin().indices().create(indexRequest, ActionListener.wrap(
                    r -> {
                        log.info("Created system index {}", feedIndexName);
                        listener.onResponse(r);
                    },
                    e -> {
                        if (e instanceof ResourceAlreadyExistsException || (e instanceof RemoteTransportException && e.getCause() instanceof ResourceAlreadyExistsException)) {
                            log.debug("index {} already exist", iocIndexMapping());
                            listener.onResponse(null);
                            return;
                        }
                        log.error("Failed to create system index {}", feedIndexName);
                        listener.onFailure(e);
                    }
            ));
        } else {
            listener.onResponse(null);
        }
    }
}

