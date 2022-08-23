/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting.model;

import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.securityanalytics.model2.AbstractModel;
import org.opensearch.securityanalytics.model2.ToXContentModel;

import java.util.List;

public class Input extends AbstractModel {

    public static NamedXContentRegistry.Entry XCONTENT_REGISTRY = ToXContentModel.createRegistryEntry(Input.class);

    public String description;
    public List<String> indices;
    public List<Query> queries;

    public Input() {
        // for serialization
    }

    public Input(final String description, final List<String> indices, final List<Query> queries) {
        this.description = description;
        this.indices = indices;
        this.queries = queries;
    }
}

