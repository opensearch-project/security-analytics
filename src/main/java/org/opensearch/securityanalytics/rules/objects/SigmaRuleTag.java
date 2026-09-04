/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import java.util.Locale;

public class SigmaRuleTag {

    private String namespace;

    private String name;

    public SigmaRuleTag(String namespace, String name) {
        this.namespace = namespace;
        this.name = name;
    }

    public static SigmaRuleTag fromStr(String tag) {
        if (tag == null || tag.trim().isEmpty()) {
            return new SigmaRuleTag("", "");
        }
        String[] tagParts = tag.split("\\.", 2);
        if (tagParts.length == 1) {
            return new SigmaRuleTag("", tagParts[0]);
        }
        return new SigmaRuleTag(tagParts[0], tagParts[1]);
    }

    public String getNamespace() {
        return namespace;
    }

    public String getName() {
        return name;
    }

    public String getFormattedTag() {
        if (namespace == null || namespace.isEmpty()) {
            return name;
        }
        return String.format(Locale.getDefault(), "%s.%s", namespace, name);
    }
}
