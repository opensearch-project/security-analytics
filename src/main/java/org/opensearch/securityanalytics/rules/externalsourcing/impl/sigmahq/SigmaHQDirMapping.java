package org.opensearch.securityanalytics.rules.externalsourcing.impl.sigmahq;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchParseException;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.securityanalytics.mapper.MapperTopicStore;

public class SigmaHQDirMapping {

    private static final String DIR_MAPPING_CONFIG_FILE = "sigmahq-dir-mapping.json";

    private static final String DIR_PATH = "dir_path";
    private static final String EXCLUDE_PATHS_WITH_PREFIX = "exclude_paths_with_prefix";
    private static final String INCLUDE_PATHS_WITH_PREFIX = "include_paths_with_prefix";
    private static final String CATEGORY_TO_DIR_MAPPING = "category_to_dir_mapping";
    private static final String CATEGORY = "category";

    private static final Logger log = LogManager.getLogger(MapperTopicStore.class);

    public static Map<String, CategoryDirMapping> ALL_CATEGORIES_MAPPING = new HashMap<>();

    static {
        new SigmaHQDirMapping();
    }

    private SigmaHQDirMapping() {

        String dirMappingConfigJson;
        try (
                InputStream is = SigmaHQDirMapping.class.getClassLoader().getResourceAsStream(DIR_MAPPING_CONFIG_FILE)
        ) {
            ALL_CATEGORIES_MAPPING = new HashMap<String, CategoryDirMapping>();
            dirMappingConfigJson = new String(Objects.requireNonNull(is).readAllBytes(), StandardCharsets.UTF_8);

            if (dirMappingConfigJson != null) {
                Map<String, Object> configMap =
                        XContentHelper.convertToMap(JsonXContent.jsonXContent, dirMappingConfigJson, false);

                List<Object> allCategories = (List<Object>) configMap.get(CATEGORY_TO_DIR_MAPPING);
                allCategories.forEach( e -> {
                    ALL_CATEGORIES_MAPPING.put(
                            ((Map<String, String>)e).get(CATEGORY),
                            CategoryDirMapping.fromMap((Map<String, Object>) e)
                    );
                });
                log.info("Loaded {} category dir mappings", ALL_CATEGORIES_MAPPING.size());
            }
        } catch (OpenSearchParseException e) {
            throw e;
        } catch (Exception e) {
            throw new SettingsException("Failed to load settings from [" + DIR_MAPPING_CONFIG_FILE + "]", e);
        }
    }

    public static CategoryDirMapping categoryDirMapping(String category) throws IOException {
        if (ALL_CATEGORIES_MAPPING.containsKey(category.toLowerCase(Locale.ROOT))) {
            return ALL_CATEGORIES_MAPPING.get(category);
        }
        throw new IllegalArgumentException("Dir mapping for category [" + category + "] not found");
    }

    public static class CategoryDirMapping {
        String dirPath;
        List<String> includePathsWithPrefix;
        List<String> excludePathsWithPrefix;

        public CategoryDirMapping(String dirPath, List<String> includePathsWithPrefix, List<String> excludePathsWithPrefix) {
            this.dirPath = dirPath;
            this.includePathsWithPrefix = includePathsWithPrefix;
            this.excludePathsWithPrefix = excludePathsWithPrefix;
        }

        public static CategoryDirMapping fromMap(Map<String, Object> dirMappingAsMap) {
            String dirPath = (String) dirMappingAsMap.get(DIR_PATH);
            List<String> includePathsWithPrefix = (List<String>) dirMappingAsMap.get(INCLUDE_PATHS_WITH_PREFIX);
            List<String> excludePathsWithPrefix = (List<String>) dirMappingAsMap.get(EXCLUDE_PATHS_WITH_PREFIX);
            return new CategoryDirMapping(
                    dirPath,
                    includePathsWithPrefix,
                    excludePathsWithPrefix
            );
        }

        public boolean isFilePassingFilters(Path file) {

            String absolutePath = file.toAbsolutePath().toString();
            String normalizedPath = absolutePath.substring(absolutePath.indexOf("/rules/"));

            if (absolutePath.endsWith(".yml") == false) {
                return false;
            }

            if (excludePathsWithPrefix != null) {
                for (String pathPrefix : excludePathsWithPrefix) {
                    if (normalizedPath.startsWith(pathPrefix)) {
                        return false;
                    }
                }
            }
            if (includePathsWithPrefix != null) {
                for (String pathPrefix : includePathsWithPrefix) {
                    if (normalizedPath.startsWith(pathPrefix)) {
                        return true;
                    }
                }
            } else {
                return true;
            }

            return false;
        }
    }
}