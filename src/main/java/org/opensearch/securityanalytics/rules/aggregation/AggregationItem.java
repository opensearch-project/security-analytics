/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.aggregation;

import java.io.Serializable;

public class AggregationItem implements Serializable {

    private static final long serialVersionUID = 1L;

    private String aggFunction;

    private String aggField;

    private String groupByField;

    private String compOperator;

    private Double threshold;

    public void setAggFunction(String aggFunction) {
        this.aggFunction = aggFunction;
    }

    public String getAggFunction() {
        return aggFunction;
    }

    public void setAggField(String aggField) {
        this.aggField = aggField;
    }

    public String getAggField() {
        return aggField;
    }

    public void setGroupByField(String groupByField) {
        this.groupByField = groupByField;
    }

    public String getGroupByField() {
        return groupByField;
    }

    public void setCompOperator(String compOperator) {
        this.compOperator = compOperator;
    }

    public String getCompOperator() {
        return compOperator;
    }

    public void setThreshold(Double threshold) {
        this.threshold = threshold;
    }

    public Double getThreshold() {
        return threshold;
    }
}