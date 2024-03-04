/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.alert;

import org.opensearch.securityanalytics.model.CorrelationAlert;

import java.util.List;

/**
 * Wrapper class that holds list of correlation alerts and total number of alerts available.
 * Useful for pagination.
 */
public class CorrelationAlertsList {

    private final List<CorrelationAlert> correlationAlertList;
    private final Long totalAlerts;

    public CorrelationAlertsList(List<CorrelationAlert> correlationAlertList, long totalAlerts) {
        this.correlationAlertList = correlationAlertList;
        this.totalAlerts = totalAlerts;
    }

    public List<CorrelationAlert> getCorrelationAlertList() {
        return correlationAlertList;
    }

    public Long getTotalAlerts() {
        return totalAlerts;
    }

}
