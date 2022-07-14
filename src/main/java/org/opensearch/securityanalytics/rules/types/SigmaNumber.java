/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.utils.Either;

public class SigmaNumber implements SigmaType {

    private Either<Integer, Float> numOpt;

    public SigmaNumber(int numOpt1) {
        this.numOpt = Either.left(numOpt1);
    }

    public SigmaNumber(float numOpt2) {
        this.numOpt = Either.right(numOpt2);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SigmaNumber that = (SigmaNumber) o;
        return (numOpt.isLeft() && that.numOpt.isLeft()) || (numOpt.isRight() && that.numOpt.isRight());
    }

    @Override
    public String toString() {
        return numOpt.isLeft() ? String.valueOf(numOpt.getLeft()): String.valueOf(numOpt.get());
    }
}