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

    private BuiltinLogTypeLoader builtinLogTypeLoader;

    public LogTypeService() {
        this.builtinLogTypeLoader = new BuiltinLogTypeLoader();
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

    /**
     * Returns sigmaRule rawField --> ECS field mapping
     *
     * @param logType Log type
     * @return Map of rawField to ecs field
     */
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