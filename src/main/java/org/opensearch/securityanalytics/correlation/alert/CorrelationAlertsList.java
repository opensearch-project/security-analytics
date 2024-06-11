/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.alert;

import org.opensearch.commons.alerting.model.CorrelationAlert;

import java.util.List;

/**
 * Wrapper class that holds list of correlation alerts and total number of alerts available.
 * Useful for pagination.
 */
public class CorrelationAlertsList {

    private final List<CorrelationAlert> correlationAlertList;
    private final Integer totalAlerts;

    public CorrelationAlertsList(List<CorrelationAlert> correlationAlertList, Integer totalAlerts) {
        this.correlationAlertList = correlationAlertList;
        this.totalAlerts = totalAlerts;
    }

    public List<CorrelationAlert> getCorrelationAlertList() {
        return correlationAlertList;
    }

    public Integer getTotalAlerts() {
        return totalAlerts;
    }

}
