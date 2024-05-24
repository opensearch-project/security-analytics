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
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.securityanalytics.model.CustomLogType;
import org.opensearch.securityanalytics.model.LogType;
import org.opensearch.securityanalytics.util.FileUtils;

public class BuiltinLogTypeLoader extends AbstractLifecycleComponent {

    private static final Logger logger = LogManager.getLogger(BuiltinLogTypeLoader.class);

    private static final String BASE_PATH = "OSMapping/";

    private static final String LOG_TYPE_FILE_SUFFIX = "_logtype.json";

    private List<LogType> logTypes;
    private Map<String, LogType> logTypeMap;

    public List<LogType> getAllLogTypes() {
        ensureLogTypesLoaded();
        return logTypes;
    }

    public LogType getLogTypeByName(String logTypeName) {
        ensureLogTypesLoaded();
        return logTypeMap.get(logTypeName);
    }

    public boolean logTypeExists(String logTypeName) {
        ensureLogTypesLoaded();
        return logTypeMap.containsKey(logTypeName);
    }

    public void ensureLogTypesLoaded() {
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

    private List<LogType> loadBuiltinLogTypes() throws URISyntaxException, IOException {
        List<LogType> logTypes = new ArrayList<>();

        String pathurl = Paths.get(BuiltinLogTypeLoader.class.getClassLoader().getResource(BASE_PATH).toURI()).toString();

        final String url = Objects.requireNonNull(BuiltinLogTypeLoader.class.getClassLoader().getResource(BASE_PATH)).toURI().toString();
        logger.error("SASHANK Path url is {}", pathurl);
        logger.error("SASHANK currently used url is {}", url);
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

    @SuppressWarnings("unchecked")
    protected List<CustomLogType> loadBuiltinLogTypesMetadata() throws URISyntaxException, IOException {
        List<CustomLogType> customLogTypes = new ArrayList<>();

        final String url = Objects.requireNonNull(BuiltinLogTypeLoader.class.getClassLoader().getResource(BASE_PATH),
                "Built-in log type metadata file not found").toURI().toString();
        Path dirPath = null;
        if (url.contains("!")) {
            final String[] paths = url.split("!");
            dirPath = FileUtils.getFs().getPath(paths[1]);
        } else {
            dirPath = Path.of(url);
        }

        Stream<Path> folder = Files.list(dirPath);
        Path logTypePath = folder.filter(e -> e.toString().endsWith("logtypes.json")).collect(Collectors.toList()).get(0);
        try (
                InputStream is = BuiltinLogTypeLoader.class.getResourceAsStream(logTypePath.toString())
        ) {
            String logTypeFilePayload = new String(Objects.requireNonNull(is).readAllBytes(), StandardCharsets.UTF_8);

            if (logTypeFilePayload != null) {
                Map<String, Object> logTypeFileAsMap =
                        XContentHelper.convertToMap(JsonXContent.jsonXContent, logTypeFilePayload, false);

                for (Map.Entry<String, Object> logType: logTypeFileAsMap.entrySet()) {
                    customLogTypes.add(new CustomLogType((Map<String, Object>) logType.getValue()));
                }
            }
        } catch (Exception e) {
            throw new SettingsException("Failed to load builtin log types", e);
        }
        return customLogTypes;
    }

    @Override
    protected void doStart() {
        ensureLogTypesLoaded();
    }

    @Override
    protected void doStop() {

    }

    @Override
    protected void doClose() throws IOException {

    }
}