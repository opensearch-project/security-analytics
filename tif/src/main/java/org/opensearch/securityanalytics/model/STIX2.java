/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class STIX2 extends IOC {
    private String type;
    @JsonProperty("spec_version")
    private String specVersion;

    public String getType() {
        return type;
    }

    public void setType(final String type) {
        this.type = type;
    }

    public String getSpecVersion() {
        return specVersion;
    }

    public void setSpecVersion(final String specVersion) {
        this.specVersion = specVersion;
    }
}
