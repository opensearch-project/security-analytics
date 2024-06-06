/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.threatIntel.sacommons;

public interface IndexTIFSourceConfigResponse {
    String getTIFConfigId();
    Long getVersion();
    TIFSourceConfigDto getTIFConfigDto();
}
