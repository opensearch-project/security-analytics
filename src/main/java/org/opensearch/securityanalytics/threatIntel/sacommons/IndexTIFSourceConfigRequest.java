/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.sacommons;

/**
 * Threat intel feed config creation request interface
 */
public interface IndexTIFSourceConfigRequest {
    String getTIFConfigId();
    TIFSourceConfigDto getTIFConfigDto();
}
