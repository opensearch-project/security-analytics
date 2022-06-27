/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.utils;

import java.util.NoSuchElementException;

final class Left<L, M, R> extends AnyOneOf<L, M, R> {

    private static final long serialVersionUID = 1L;

    private final L value;

    public Left(L value) {
        this.value = value;
    }

    @Override
    public L getLeft() {
        return value;
    }

    @Override
    public boolean isLeft() {
        return true;
    }

    @Override
    public boolean isRight() {
        return false;
    }

    @Override
    public R get() {
        throw new NoSuchElementException("get() on Left");
    }

    @Override
    public M getMiddle() {
        throw new NoSuchElementException("getMiddle() on Middle");
    }

    @Override
    public boolean isMiddle() {
        return false;
    }
}