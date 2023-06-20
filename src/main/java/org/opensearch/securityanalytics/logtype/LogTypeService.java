/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.logtype;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.securityanalytics.model.LogType;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;


/**
 *
 * */
public class LogTypeService {

    private static final Logger logger = LogManager.getLogger(LogTypeService.class);

    private BuiltinLogTypeLoader builtinLogTypeLoader;

    public LogTypeService() {
        this.builtinLogTypeLoader = new BuiltinLogTypeLoader();
    }


    public List<LogType> getAllLogTypes() {
        return BuiltinLogTypeLoader.getAllLogTypes();
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