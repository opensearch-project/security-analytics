package org.opensearch.securityanalytics.util;

import kotlin.Triple;
import org.opensearch.Version;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.regex.Regex;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsModule;
import org.opensearch.common.util.BigArrays;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.index.Index;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.analysis.IndexAnalyzers;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.index.query.QueryShardContext;
import org.opensearch.index.similarity.SimilarityService;
import org.opensearch.indices.IndicesModule;
import org.opensearch.indices.analysis.AnalysisModule;
import org.opensearch.indices.mapper.MapperRegistry;
import org.opensearch.plugins.MapperPlugin;
import org.opensearch.plugins.PluginsService;
import org.opensearch.script.ScriptService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

public class QueryShardContextFactory {

    private final Client client;

    private final ClusterService clusterService;

    private final ScriptService scriptService;

    private final NamedXContentRegistry xContentRegistry;

    private final NamedWriteableRegistry namedWriteableRegistry;

    private final Environment environment;

    public QueryShardContextFactory(Client client,
                                    ClusterService clusterService,
                                    ScriptService scriptService,
                                    NamedXContentRegistry xContentRegistry,
                                    NamedWriteableRegistry namedWriteableRegistry,
                                    Environment environment) {
        this.client = client;
        this.clusterService = clusterService;
        this.scriptService = scriptService;
        this.xContentRegistry = xContentRegistry;
        this.namedWriteableRegistry = namedWriteableRegistry;
        this.environment = environment;
    }

    private Triple<Index, Settings, IndexMetadata> getIndexSettingsAndMetadata(String indexName) {
        Index index = null;
        Settings indexSettings = null;
        IndexMetadata indexMetadata = clusterService.state().metadata().index(indexName);
        if (indexMetadata == null) {
            throw new IllegalArgumentException("Can't find IndexMetadata for index: " + indexName);
        }
        index = indexMetadata.getIndex();
        indexSettings = indexMetadata.getSettings();
        return new Triple<>(index, indexSettings, indexMetadata);
    }

    public QueryShardContext createShardContext(String indexName) throws IOException {
        Triple<Index, Settings, IndexMetadata> indexSettingsIndexMetadata = getIndexSettingsAndMetadata(indexName);
        Index index = indexSettingsIndexMetadata.getFirst();
        Settings indexSettings = indexSettingsIndexMetadata.getSecond();
        IndexMetadata indexMetadata = indexSettingsIndexMetadata.getThird();

        Settings nodeSettings = Settings.builder()
                .put("node.name", "dummyNodeName")
                .put(Environment.PATH_HOME_SETTING.getKey(), environment.tmpDir())
                .build();
        PluginsService pluginsService = new PluginsService(nodeSettings, null, null, null, List.of());
        List<Setting<?>> additionalSettings = pluginsService.getPluginSettings();
        SettingsModule settingsModule = new SettingsModule(nodeSettings,
                additionalSettings,
                pluginsService.getPluginSettingsFilter(), HashSet.newHashSet(0));
        IndexScopedSettings indexScopedSettings = settingsModule.getIndexScopedSettings();
        IndexSettings idxSettings = newIndexSettings(index, indexSettings, indexScopedSettings);
        IndicesModule indicesModule = new IndicesModule(pluginsService.filterPlugins(MapperPlugin.class));
        MapperRegistry mapperRegistry = indicesModule.getMapperRegistry();
        AnalysisModule analysisModule = new AnalysisModule(environment, List.of());
        IndexAnalyzers indexAnalyzers = analysisModule.getAnalysisRegistry().build(idxSettings);
        SimilarityService similarityService = new SimilarityService(idxSettings, null, Map.of());
        MapperService mapperService = new MapperService(
                idxSettings,
                indexAnalyzers,
                xContentRegistry,
                similarityService,
                mapperRegistry,
                () -> {
                    try {
                        return createShardContext(null);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                },
                () -> false,
                scriptService
        );
        mapperService.merge("_doc", indexMetadata.mapping().source(), MapperService.MergeReason.MAPPING_UPDATE);
        return new QueryShardContext(
                0,
                idxSettings,
                BigArrays.NON_RECYCLING_INSTANCE,
                null,
                null,
                mapperService,
                null,
                scriptService,
                xContentRegistry,
                namedWriteableRegistry,
                null,
                null,
                () -> Instant.now().toEpochMilli() ,
                null,
                (pattern) -> Regex.simpleMatch(pattern, index.getName()),
                () -> true,
                null);
    }

    private IndexSettings newIndexSettings(Index index, Settings settings, IndexScopedSettings indexScopedSettings) {
        Settings build = Settings.builder()
                .put(IndexMetadata.SETTING_VERSION_CREATED, Version.CURRENT)
                .put(IndexMetadata.SETTING_NUMBER_OF_REPLICAS, 1)
                .put(IndexMetadata.SETTING_NUMBER_OF_SHARDS, 1)
                .put(settings)
                .build();

        IndexMetadata metadata = null;
        if (index.getName() != null) {
            metadata = IndexMetadata.builder(index.getName()).settings(build).build();
        }
        return new IndexSettings(metadata, Settings.EMPTY, indexScopedSettings);
    }
}