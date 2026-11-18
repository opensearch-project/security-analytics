/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.utils.Either;

public class SigmaNumber implements SigmaType {

    private Either<Number, Number> numOpt;

    public SigmaNumber(int numOpt1) {
        this.numOpt = Either.left(numOpt1);
    }

    public SigmaNumber(float numOpt2) {
        this.numOpt = Either.right(numOpt2);
    }

    public SigmaNumber(long number) {
        this.numOpt = Either.left(number);
    }

    public SigmaNumber(double number) {
        this.numOpt = Either.right(number);
    }

    public String getMappingType() {
        Number number = numOpt.isLeft() ? numOpt.getLeft() : numOpt.get();
        return number instanceof Integer ? "integer" : number instanceof Long ? "long" : number instanceof Float ? "float" : "double";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SigmaNumber that = (SigmaNumber) o;
        return (numOpt.isLeft() && that.numOpt.isLeft()) || (numOpt.isRight() && that.numOpt.isRight());
    }

    public Either<Number, Number> getNumOpt() {
        return numOpt;
    }

    @Override
    public String toString() {
        return numOpt.isLeft() ? String.valueOf(numOpt.getLeft()): String.valueOf(numOpt.get());
    }
}