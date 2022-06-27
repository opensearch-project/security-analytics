/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.utils;

public abstract class AnyOneOf<L, M, R> extends Either<L, R> {

    private static final long serialVersionUID = 1L;

    AnyOneOf() {
        super();
    }

    public static <L, M, R> AnyOneOf<L, M, R> leftVal(L left) {
        return new Left<>(left);
    }

    public static <L, M, R> AnyOneOf<L, M, R> rightVal(R right) {
        return new Right<>(right);
    }

    public static <L, M, R> AnyOneOf<L, M, R> middleVal(M middle) {
        return new Middle<>(middle);
    }

    public abstract M getMiddle();

    public abstract boolean isMiddle();
}