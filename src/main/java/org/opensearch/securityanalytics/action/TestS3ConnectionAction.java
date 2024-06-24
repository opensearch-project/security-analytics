/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class TestS3ConnectionAction extends ActionType<TestS3ConnectionResponse> {
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/connections/test/s3";
    public static final TestS3ConnectionAction INSTANCE = new TestS3ConnectionAction();

    public TestS3ConnectionAction() {
        super(NAME, TestS3ConnectionResponse::new);
    }
}
