/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.opensearch.commons.authuser.User;

import java.time.Instant;
import java.util.List;

public class Detector {

    private String id;

    private Long version;

    private String name;

    private Boolean enabled;

    private Schedule schedule;

    private Instant lastUpdateTime;

    private Instant enabledTime;

    private String detectorType;

    private User user;

    private Integer schemaVersion;

    private List<DetectorInput> inputs;
}