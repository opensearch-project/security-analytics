/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.utils;

import java.io.Serializable;

public abstract class Either<L, R> implements Serializable {

    private static final long serialVersionUID = 1L;

    Either() {
    }

    public static <L, R> Either<L, R> right(R right) {
        return new Right<>(right);
    }

    public static <L, R> Either<L, R> left(L left) {
        return new Left<>(left);
    }

    public abstract L getLeft();

    public abstract boolean isLeft();

    public abstract boolean isRight();

    public abstract R get();
}