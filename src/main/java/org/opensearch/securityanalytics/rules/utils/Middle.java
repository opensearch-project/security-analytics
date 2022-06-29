/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.utils;

import java.util.NoSuchElementException;

final class Middle<L, M, R> extends AnyOneOf<L, M, R> {

    private static final long serialVersionUID = 1L;

    private final M value;

    public Middle(M value) {
        this.value = value;
    }

    @Override
    public M getMiddle() {
        return value;
    }

    @Override
    public boolean isMiddle() {
        return true;
    }

    @Override
    public L getLeft() {
        throw new NoSuchElementException("getLeft() on Middle");
    }

    @Override
    public boolean isLeft() {
        return false;
    }

    @Override
    public boolean isRight() {
        return false;
    }

    @Override
    public R get() {
        throw new NoSuchElementException("get() on Middle");
    }
}