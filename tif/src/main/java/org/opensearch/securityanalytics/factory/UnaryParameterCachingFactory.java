/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.factory;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public abstract class UnaryParameterCachingFactory<T, U> {
    private final Cache<T, U> cache;

    public UnaryParameterCachingFactory() {
        this.cache = CacheBuilder.newBuilder().build();
    }

    protected abstract U doCreate(T parameter);

    public U create(T parameter) {
        if (cache.getIfPresent(parameter) == null) {
            cache.put(parameter, doCreate(parameter));
        }

        return cache.getIfPresent(parameter);
    }
}
