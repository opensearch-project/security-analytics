/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchParseException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.securityanalytics.mapper.MapperTopicStore;

public class RuleCategory implements Writeable, ToXContentObject {

    private static final Logger log = LogManager.getLogger(RuleCategory.class);

    public static final String KEY = "key";
    public static final String DISPLAY_NAME = "display_name";
    public static final String ENABLED = "enabled";

    private String name;
    private String displayName;
    private Boolean enabled;

    public RuleCategory(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readString(), sin.readBoolean());
    }

    public RuleCategory(String name, String displayName, Boolean enabled) {
        this.name = name;
        this.displayName = displayName;
        this.enabled = enabled;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeString(displayName);
        out.writeBoolean(enabled);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(KEY, name)
                .field(DISPLAY_NAME, displayName)
                .field(ENABLED, enabled)
                .endObject();
    }

    public String getName() {
        return name;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    private void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    private static final String RULE_CATEGORIES_CONFIG_FILE = "rules/rule_categories.json";

    // Rule category is the same as detector type
    public static final List<RuleCategory> ALL_RULE_CATEGORIES;

    static {
        List<RuleCategory> ruleCategories = new ArrayList<>();
        String ruleCategoriesJson;
        try (
                InputStream is = RuleCategory.class.getClassLoader().getResourceAsStream(RULE_CATEGORIES_CONFIG_FILE)
        ) {
            ruleCategoriesJson = new String(Objects.requireNonNull(is).readAllBytes(), StandardCharsets.UTF_8);

            if (ruleCategoriesJson != null) {
                Map<String, Object> configMap =
                        XContentHelper.convertToMap(JsonXContent.jsonXContent, ruleCategoriesJson, false);
                List<Map<String, Object>> categories = (List<Map<String, Object>>) configMap.get("rule_categories");
                for (Map<String, Object> c : categories) {
                    ruleCategories.add(new RuleCategory(
                            (String) c.get(KEY),
                            (String) c.get(DISPLAY_NAME),
                            (Boolean) c.get(ENABLED)
                    ));
                }
            }
        } catch (OpenSearchParseException e) {
            throw e;
        } catch (Exception e) {
            throw new SettingsException("Failed to load settings from [" + RULE_CATEGORIES_CONFIG_FILE + "]", e);
        }
        // Go through all categories from config and disable ones which are not found in DetectorType enum.
        // Disabling rule category would prevent it from showing on UI on "Create Detector" page
        List<String> detectorTypes = Arrays.stream(Detector.DetectorType.values())
                .map(Detector.DetectorType::getDetectorType)
                .collect(Collectors.toList());

        for (RuleCategory c : ruleCategories) {
            if (detectorTypes.contains(c.name) == false) {
                c.setEnabled(false);
                log.warn("Rule category: [" + c.getName() + "] from config is not present in DetectorType enum!");
            }
        }
        ALL_RULE_CATEGORIES = Collections.unmodifiableList(ruleCategories);
    }
}

