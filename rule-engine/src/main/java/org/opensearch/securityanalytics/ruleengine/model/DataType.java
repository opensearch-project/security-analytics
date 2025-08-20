/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.model;

import java.util.HashMap;
import java.util.Map;

public abstract class DataType {
    private final Map<String, String> dataTypeMetadata;

    public DataType() {
        this.dataTypeMetadata = new HashMap<>();
    }

    public abstract Object getValue(String fieldName);
    public abstract String getTimeFieldName();

    public void putDataTypeMetadata(final String key, final String value) {
        dataTypeMetadata.put(key, value);
    }

    public Map<String, String> getDataTypeMetadata() {
        return dataTypeMetadata;
    }
}
