/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.logtype;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.securityanalytics.model.LogType;
import org.opensearch.securityanalytics.util.FileUtils;

public class BuiltinLogTypeLoader {

    private static final Logger logger = LogManager.getLogger(BuiltinLogTypeLoader.class);

    private static final String BASE_PATH = "OSMapping/";

    private static final String LOG_TYPE_FILE_SUFFIX = "_logtype.json";

    private static List<LogType> logTypes;
    private static Map<String, LogType> logTypeMap;


    static {
        ensureLogTypesLoaded();
    }

    public static List<LogType> getAllLogTypes() {
        ensureLogTypesLoaded();
        return logTypes;
    }

    public static LogType getLogTypeByName(String logTypeName) {
        ensureLogTypesLoaded();
        return logTypeMap.get(logTypeName);
    }

    public static boolean logTypeExists(String logTypeName) {
        ensureLogTypesLoaded();
        return logTypeMap.containsKey(logTypeName);
    }

    private static void ensureLogTypesLoaded() {
        try {
            if (logTypes != null) {
                return;
            }
            logTypes = loadBuiltinLogTypes();
            logTypeMap = logTypes.stream()
                    .collect(Collectors.toMap(LogType::getName, Function.identity()));
        } catch (Exception e) {
            logger.error("Failed loading builtin log types from disk!", e);
        }
    }

    private static List<LogType> loadBuiltinLogTypes() throws URISyntaxException, IOException {
        List<LogType> logTypes = new ArrayList<>();

        final String url = Objects.requireNonNull(BuiltinLogTypeLoader.class.getClassLoader().getResource(BASE_PATH)).toURI().toString();

        Path dirPath = null;
        if (url.contains("!")) {
            final String[] paths = url.split("!");
            dirPath = FileUtils.getFs().getPath(paths[1]);
        } else {
            dirPath = Path.of(url);
        }

        Stream<Path> folder = Files.list(dirPath);
        List<Path> logTypePaths = folder.filter(e -> e.toString().endsWith(LOG_TYPE_FILE_SUFFIX)).collect(Collectors.toList());

        for (Path logTypePath : logTypePaths) {
            try (
                InputStream is = BuiltinLogTypeLoader.class.getResourceAsStream(logTypePath.toString())
            ) {
                String logTypeFilePayload = new String(Objects.requireNonNull(is).readAllBytes(), StandardCharsets.UTF_8);

                if (logTypeFilePayload != null) {
                    Map<String, Object> logTypeFileAsMap =
                            XContentHelper.convertToMap(JsonXContent.jsonXContent, logTypeFilePayload, false);

                    logTypes.add(new LogType(logTypeFileAsMap));

                    logger.info("Loaded [{}] log type", logTypePath.getFileName());
                }
            } catch (Exception e) {
                throw new SettingsException("Failed to load builtin log types", e);
            }
        }

        return logTypes;
    }
}
