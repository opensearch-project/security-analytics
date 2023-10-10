/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

/**
 * Task that {@link TIFJobRunner} will run
 */
public enum TIFJobTask {
    /**
     * Do everything
     */
    ALL,

    /**
     * Only delete unused indices
     */
    DELETE_UNUSED_INDICES
}
