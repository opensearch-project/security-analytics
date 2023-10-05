/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.jobscheduler;

/**
 * Task that {@link DatasourceRunner} will run
 */
public enum DatasourceTask {
    /**
     * Do everything
     */
    ALL,

    /**
     * Only delete unused indices
     */
    DELETE_UNUSED_INDICES
}
