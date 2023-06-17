/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.logtype;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.BaseExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.Client;
import org.opensearch.client.OriginSettingClient;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.io.Streams;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.securityanalytics.model.LogType;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.action.admin.cluster.node.tasks.get.GetTaskAction.TASKS_ORIGIN;
import static org.opensearch.common.xcontent.XContentFactory.jsonBuilder;


/**
 *
 * */
public class LogTypeService {

    private static final Logger logger = LogManager.getLogger(LogTypeService.class);

    public static final String LOG_TYPE_INDEX = ".opensearch-sap-log-types-config";

    public static final String LOG_TYPE_INDEX_MAPPING_FILE = "log_type_config_mapping.json";

    public static final String LOG_TYPE_MAPPING_VERSION_META_FIELD = "schema_version";

    public static final int LOG_TYPE_MAPPING_VERSION = 1; // must match version in log_type_config_mapping.json

    private boolean isConfigIndexInitialized;

    private final Client client;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private BuiltinLogTypeLoader builtinLogTypeLoader;

    @Inject
    public LogTypeService(Client client, ClusterService clusterService, ThreadPool threadPool) {
        this.client = new OriginSettingClient(client, TASKS_ORIGIN);
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.builtinLogTypeLoader = new BuiltinLogTypeLoader();
    }

    public void indexLogType(LogType logType, ActionListener<Void> listener) {
        ensureConfigIndexIsCreated(ActionListener.wrap(e -> {

            IndexRequest indexRequest = new IndexRequest(LOG_TYPE_INDEX);
            indexRequest.source(logType.toXContent(XContentFactory.jsonBuilder(), null));
//            indexRequest.create()
        }, listener::onFailure));
    }

    public void ensureConfigIndexIsCreated(ActionListener<Void> listener) {

        if (isConfigIndexInitialized) {
            listener.onResponse(null);
        }

        ClusterState state = clusterService.state();

        if (state.routingTable().hasIndex(LOG_TYPE_INDEX) == false) {
            CreateIndexRequest createIndexRequest = new CreateIndexRequest();
            createIndexRequest.settings(logTypeIndexSettings());
            createIndexRequest.index(LOG_TYPE_INDEX);
            createIndexRequest.mapping(logTypeIndexMapping());
            createIndexRequest.cause("auto(sap-logtype api)");

            client.admin().indices().create(createIndexRequest, new ActionListener<CreateIndexResponse>() {
                @Override
                public void onResponse(CreateIndexResponse result) {
                    listener.onResponse(null);
                }

                @Override
                public void onFailure(Exception e) {
                    if (BaseExceptionsHelper.unwrapCause(e) instanceof ResourceAlreadyExistsException) {
                        isConfigIndexInitialized = true;
                        listener.onResponse(null);
                    } else {
                        listener.onFailure(e);
                    }
                }
            });
        } else {
            IndexMetadata metadata = state.getMetadata().index(LOG_TYPE_INDEX);
            if (getConfigIndexMappingVersion(metadata) < LOG_TYPE_MAPPING_VERSION) {
                // The index already exists but doesn't have our mapping
                client.admin()
                        .indices()
                        .preparePutMapping(LOG_TYPE_INDEX)
                        .setSource(logTypeIndexMapping(), XContentType.JSON)
                        .execute(ActionListener.delegateFailure(listener, (l, r) -> {
                            isConfigIndexInitialized = true;
                            listener.onResponse(null);
                        }));
            } else {
                isConfigIndexInitialized = true;
                listener.onResponse(null);
            }
        }
    }

    public String logTypeIndexMapping() {
        try (InputStream is = getClass().getResourceAsStream(LOG_TYPE_INDEX_MAPPING_FILE)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Streams.copy(is, out);
            return out.toString(StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            logger.error(
                    () -> new ParameterizedMessage("failed to load log-type-index mapping file [{}]", LOG_TYPE_INDEX_MAPPING_FILE),
                    e
            );
            throw new IllegalStateException("failed to load log-type-index mapping file [" + LOG_TYPE_INDEX_MAPPING_FILE + "]", e);
        }

    }

    private Settings logTypeIndexSettings() {
        return Settings.builder().put(IndexMetadata.INDEX_HIDDEN_SETTING.getKey(), "true").build();
    }

    private int getConfigIndexMappingVersion(IndexMetadata metadata) {
        MappingMetadata mappingMetadata = metadata.mapping();
        if (mappingMetadata == null) {
            return 0;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> meta = (Map<String, Object>) mappingMetadata.sourceAsMap().get("_meta");
        if (meta == null || meta.containsKey(LOG_TYPE_MAPPING_VERSION_META_FIELD) == false) {
            return 1; // The mapping was created before meta field was introduced
        }
        return (int) meta.get(LOG_TYPE_MAPPING_VERSION_META_FIELD);
    }

    public boolean logTypeExists(String logTypeName) {
        return BuiltinLogTypeLoader.logTypeExists(logTypeName);
    }

    public List<LogType> getAllLogTypes() {
        return BuiltinLogTypeLoader.getAllLogTypes();
    }

    public Set<String> getRequiredFields(String logType) throws IOException {
        Optional<LogType> lt = getAllLogTypes()
                .stream()
                .filter(l -> l.getName().equals(logType))
                .findFirst();
        if (lt.isEmpty()) {
            throw SecurityAnalyticsException.wrap(new IllegalArgumentException("Can't get rule field mappings for invalid logType: [" + logType + "]"));
        }
        return getRequiredFields(lt.get());
    }

    public Set<String> getRequiredFields(LogType logType) throws IOException {
        Objects.requireNonNull(logType, "Can't retrieve required fields for null Log Type!");

        if (logType.getMappings() != null) {
            return logType.getMappings()
                    .stream()
                    .map(e -> e.getEcs())
                    .collect(Collectors.toSet());
        } else {
            return Set.of();
        }
    }

    public String aliasMappings(String logType) throws IOException {
        Optional<LogType> lt = getAllLogTypes()
                .stream()
                .filter(l -> l.getName().equals(logType))
                .findFirst();
        if (lt.isEmpty()) {
            throw SecurityAnalyticsException.wrap(new IllegalArgumentException("Can't get rule field mappings for invalid logType: [" + logType + "]"));
        }
        return aliasMappings(lt.get());
    }
    // TODO our mappings APIs dont actually need "alias mappings". We can just return a list of required fields
    public String aliasMappings(LogType logType) throws IOException {
        Objects.requireNonNull(logType, "Can't retrieve aliasMappings for null LogType!");

        XContentBuilder builder = jsonBuilder()
                .startObject()
                .startObject("properties");

        if (logType.getMappings() != null) {
            // Convert it to Set as we can have multiple ecs fields with same name
            Set<String> ecsFields = logType.getMappings()
                    .stream()
                    .map(e -> e.getEcs())
                    .collect(Collectors.toSet());

            for (String ecsField : ecsFields) {
                builder.startObject(ecsField)
                        .field("type", "alias")
                        .field("path", ecsField)
                        .endObject();
            }
        }
        builder.endObject()
                .endObject();

        return org.opensearch.common.Strings.toString(builder);
    }

    public Map<String, String> getRuleFieldMappings(String logType) {
        Optional<LogType> lt = getAllLogTypes()
                .stream()
                .filter(l -> l.getName().equals(logType))
                .findFirst();

        if (lt.isEmpty()) {
            throw SecurityAnalyticsException.wrap(new IllegalArgumentException("Can't get rule field mappings for invalid logType: [" + logType + "]"));
        }
        if (lt.get().getMappings() == null) {
            return Map.of();
        } else {
            return lt.get().getMappings()
                    .stream()
                    .collect(Collectors.toMap(LogType.Mapping::getRawField, LogType.Mapping::getEcs));
        }
    }
}
