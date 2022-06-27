/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.utils;

import java.util.NoSuchElementException;

final class Right<L, M, R> extends AnyOneOf<L, M, R> {

    private static final long serialVersionUID = 1L;

    private final R value;

    public Right(R value) {
        this.value = value;
    }

    @Override
    public L getLeft() {
        throw new NoSuchElementException("getLeft() on Right");
    }

    @Override
    public boolean isLeft() {
        return false;
    }

    @Override
    public boolean isRight() {
        return true;
    }

    @Override
    public R get() {
        return value;
    }

    @Override
    public M getMiddle() {
        throw new NoSuchElementException("getMiddle() on Right");
    }

    @Override
    public boolean isMiddle() {
        return false;
    }
}