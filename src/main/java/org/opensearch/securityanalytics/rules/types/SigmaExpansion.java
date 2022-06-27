/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import java.util.List;

public class SigmaExpansion implements SigmaType {

    private List<SigmaType> values;

    public SigmaExpansion(List<SigmaType> values) {
        this.values = values;
    }

    public void setValues(List<SigmaType> values) {
        this.values = values;
    }

    public List<SigmaType> getValues() {
        return values;
    }
}