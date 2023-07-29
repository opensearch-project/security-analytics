/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;

public class DeleteCustomLogTypeAction extends ActionType<DeleteCustomLogTypeResponse> {

    public static final DeleteCustomLogTypeAction INSTANCE = new DeleteCustomLogTypeAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/logtype/delete";

    public DeleteCustomLogTypeAction() {
        super(NAME, DeleteCustomLogTypeResponse::new);
    }
}