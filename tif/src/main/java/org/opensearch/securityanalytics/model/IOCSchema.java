/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

public enum IOCSchema {
    STIX2(STIX2.class);

    private final Class<? extends IOC> modelClass;

    IOCSchema(final Class<? extends IOC> modelClass) {
        this.modelClass = modelClass;
    }

    public Class<? extends IOC> getModelClass() {
        return modelClass;
    }
}
