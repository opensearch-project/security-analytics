/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.dao;

import java.io.IOException;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.cache.Cache;
import org.opensearch.common.cache.CacheBuilder;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.shard.IndexingOperationListener;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelFeedDataService;
import org.opensearch.securityanalytics.threatIntel.common.DatasourceState;
import org.opensearch.securityanalytics.threatIntel.jobscheduler.Datasource;

/**
 * Data access object for Datasource and threat intel feed with added caching layer
 *
 * ThreatIntelFeedCachedDao has a memory cache to store Datasource and threat intel feed. To fully utilize the cache,
 * do not create multiple ThreatIntelFeedCachedDao. ThreatIntelFeedCachedDao instance is bound to guice so that you can use
 * it through injection.
 *
 * All threat intel processors share single ThreatIntelFeedCachedDao instance.
 */
public class ThreatIntelCachedDao implements IndexingOperationListener {

    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    private final DatasourceDao datasourceDao;
    private final ThreatIntelFeedDataService threatIntelFeedDataService;
    private final ThreatIntelDataCache threatIntelDataCache;
    private Map<String, DatasourceMetadata> metadata;

    public ThreatIntelCachedDao(final ClusterService clusterService, final DatasourceDao datasourceDao, final ThreatIntelFeedDataService threatIntelFeedDataService) {
        this.datasourceDao = datasourceDao;
        this.threatIntelFeedDataService = threatIntelFeedDataService;
        this.threatIntelDataCache = new ThreatIntelDataCache(clusterService.getClusterSettings().get(SecurityAnalyticsSettings.CACHE_SIZE));
        clusterService.getClusterSettings()
                .addSettingsUpdateConsumer(SecurityAnalyticsSettings.CACHE_SIZE, setting -> this.threatIntelDataCache.updateMaxSize(setting.longValue()));
    }

    public String getIndexName(final String datasourceName) {
        return getMetadata().getOrDefault(datasourceName, DatasourceMetadata.EMPTY_METADATA).getIndexName();
    }

    public boolean has(final String datasourceName) {
        return getMetadata().containsKey(datasourceName);
    }

    public DatasourceState getState(final String datasourceName) {
        return getMetadata().getOrDefault(datasourceName, DatasourceMetadata.EMPTY_METADATA).getState();
    }

    public Map<String, Object> getThreatIntelData(final String indexName, final String ip) {
        try {
            return threatIntelDataCache.putIfAbsent(indexName, ip, addr -> threatIntelFeedDataService.getThreatIntelData(indexName, ip));
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    private Map<String, DatasourceMetadata> getMetadata() {
        if (metadata != null) {
            return metadata;
        }
        synchronized (this) {
            if (metadata != null) {
                return metadata;
            }
            Map<String, DatasourceMetadata> tempData = new ConcurrentHashMap<>();
            try {
                datasourceDao.getAllDatasources()
                        .stream()
                        .forEach(datasource -> tempData.put(datasource.getName(), new DatasourceMetadata(datasource)));
            } catch (IndexNotFoundException e) {
                log.debug("Datasource has never been created");
            }
            metadata = tempData;
            return metadata;
        }
    }

    private void put(final Datasource datasource) {
        DatasourceMetadata metadata = new DatasourceMetadata(datasource);
        getMetadata().put(datasource.getName(), metadata);
    }

    private void remove(final String datasourceName) {
        getMetadata().remove(datasourceName);
    }

    @Override
    public void postIndex(ShardId shardId, Engine.Index index, Engine.IndexResult result) {
        if (Engine.Result.Type.FAILURE.equals(result.getResultType())) {
            return;
        }

        try {
            XContentParser parser = XContentType.JSON.xContent()
                    .createParser(NamedXContentRegistry.EMPTY, LoggingDeprecationHandler.INSTANCE, index.source().utf8ToString());
            parser.nextToken();
            Datasource datasource = Datasource.PARSER.parse(parser, null);
            put(datasource);
        } catch (IOException e) {
            log.error("IOException occurred updating datasource metadata for datasource {} ", index.id(), e);
        }
    }

    @Override
    public void postDelete(ShardId shardId, Engine.Delete delete, Engine.DeleteResult result) {
        if (result.getResultType().equals(Engine.Result.Type.FAILURE)) {
            return;
        }
        remove(delete.id());
    }

    private static class DatasourceMetadata {
        private static DatasourceMetadata EMPTY_METADATA = new DatasourceMetadata();
        private String indexName;
        private DatasourceState state;

        private DatasourceMetadata() {
        }

        public DatasourceMetadata(final Datasource datasource) {
            this.indexName = datasource.currentIndexName();
            this.state = datasource.getState();
        }

        public String getIndexName() {
            return indexName;
        }

        public DatasourceState getState() {
            return state;
        }
    }

    /**
     * Cache to hold threat intel data
     *
     * ThreatIntelData in an index in immutable. Therefore, invalidation is not needed.
     */
    protected static class ThreatIntelDataCache {
        private Cache<CacheKey, Map<String, Object>> cache;

        public ThreatIntelDataCache(final long maxSize) {
            if (maxSize < 0) {
                throw new IllegalArgumentException("threat intel max cache size must be 0 or greater");
            }
            this.cache = CacheBuilder.<CacheKey, Map<String, Object>>builder().setMaximumWeight(maxSize).build();
        }

        public Map<String, Object> putIfAbsent(
                final String indexName,
                final String ip,
                final Function<String, Map<String, Object>> retrieveFunction
        ) throws ExecutionException {
            CacheKey cacheKey = new CacheKey(indexName, ip);
            return cache.computeIfAbsent(cacheKey, key -> retrieveFunction.apply(key.ip));
        }

        public Map<String, Object> get(final String indexName, final String ip) {
            return cache.get(new CacheKey(indexName, ip));
        }

        /**
         * Create a new cache with give size and replace existing cache
         *
         * Try to populate the existing value from previous cache to the new cache in best effort
         *
         * @param maxSize
         */
        public void updateMaxSize(final long maxSize) {
            if (maxSize < 0) {
                throw new IllegalArgumentException("threat intel max cache size must be 0 or greater");
            }
            Cache<CacheKey, Map<String, Object>> temp = CacheBuilder.<CacheKey, Map<String, Object>>builder()
                    .setMaximumWeight(maxSize)
                    .build();
            int count = 0;
            Iterator<CacheKey> it = cache.keys().iterator();
            while (it.hasNext() && count < maxSize) {
                CacheKey key = it.next();
                temp.put(key, cache.get(key));
                count++;
            }
            cache = temp;
        }

        private static class CacheKey {
            private final String indexName;
            private final String ip;

            public CacheKey(final String indexName, final String ip) {
                this.indexName = indexName;
                this.ip = ip;
            }
        }
    }
}
