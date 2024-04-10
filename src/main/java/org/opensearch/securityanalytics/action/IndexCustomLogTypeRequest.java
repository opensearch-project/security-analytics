/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.model.CustomLogType;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IndexCustomLogTypeRequest extends ActionRequest {

    private String logTypeId;

    private WriteRequest.RefreshPolicy refreshPolicy;

    private RestRequest.Method method;

    private CustomLogType customLogType;

    private static final Pattern IS_VALID_CUSTOM_LOG_NAME = Pattern.compile("[a-z0-9_-]{2,50}");

    public IndexCustomLogTypeRequest(
            String logTypeId,
            WriteRequest.RefreshPolicy refreshPolicy,
            RestRequest.Method method,
            CustomLogType customLogType
    ) {
        super();
        this.logTypeId = logTypeId;
        this.refreshPolicy = refreshPolicy;
        this.method = method;
        this.customLogType = customLogType;
    }

    public IndexCustomLogTypeRequest(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                WriteRequest.RefreshPolicy.readFrom(sin),
                sin.readEnum(RestRequest.Method.class),
                CustomLogType.readFrom(sin)
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        Matcher matcher = IS_VALID_CUSTOM_LOG_NAME.matcher(customLogType.getName());
        boolean find = matcher.matches();
        if (!find) {
            throw new ActionRequestValidationException();
        }
        String category = customLogType.getCategory();
        if (!CustomLogType.VALID_LOG_CATEGORIES.contains(category)) {
            throw new ActionRequestValidationException();
        }
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(logTypeId);
        refreshPolicy.writeTo(out);
        out.writeEnum(method);
        customLogType.writeTo(out);
    }

    public String getLogTypeId() {
        return logTypeId;
    }

    public WriteRequest.RefreshPolicy getRefreshPolicy() {
        return refreshPolicy;
    }

    public RestRequest.Method getMethod() {
        return method;
    }

    public CustomLogType getCustomLogType() {
        return customLogType;
    }
}