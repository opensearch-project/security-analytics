/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.opensearch.OpenSearchParseException;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.settings.SettingsException;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.json.JsonXContent;

public class RuleCategory implements Writeable, ToXContentObject {

    public static final String KEY = "key";
    public static final String DISPLAY_NAME = "display_name";

    private String name;
    private String displayName;

    public RuleCategory(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readString());
    }

    public RuleCategory(String name, String displayName) {
        this.name = name;
        this.displayName = displayName;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeString(displayName);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(KEY, name)
                .field(DISPLAY_NAME, displayName)
                .endObject();
    }

    public String getName() {
        return name;
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
                            (String) c.get(DISPLAY_NAME)
                    ));
                }
            }
        } catch (OpenSearchParseException e) {
            throw e;
        } catch (Exception e) {
            throw new SettingsException("Failed to load settings from [" + RULE_CATEGORIES_CONFIG_FILE + "]", e);
        }
        ALL_RULE_CATEGORIES = Collections.unmodifiableList(ruleCategories);
    }
}

