package org.opensearch.securityanalytics.factory;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;

public abstract class BinaryParameterCachingFactory<T, U, V> {
    private final Table<T, U, V> cache;

    public BinaryParameterCachingFactory() {
        this.cache = HashBasedTable.create();
    }

    protected abstract V doCreate(T parameter1, U parameter2);

    public V create(final T parameter1, final U parameter2) {
        if (!cache.contains(parameter1, parameter2)) {
            cache.put(parameter1, parameter2, doCreate(parameter1, parameter2));
        }

        return cache.get(parameter1, parameter2);
    }
}
