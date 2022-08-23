/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model2;

import org.opensearch.common.ParseField;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Locale;

public interface ToXContentModel extends ToXContentObject {

    static NamedXContentRegistry.Entry createRegistryEntry(final Class<? extends ToXContentModel> modelClass) {
        return new NamedXContentRegistry.Entry(modelClass, new ParseField(modelClass.getSimpleName().toLowerCase(Locale.getDefault())), parser -> ModelSerializer.read(parser, modelClass));
    }

    @Override
    default XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        return ModelSerializer.write(builder, this);
    }
}