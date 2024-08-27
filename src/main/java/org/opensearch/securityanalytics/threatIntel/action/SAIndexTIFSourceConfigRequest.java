/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.threatIntel.common.SourceConfigDtoValidator;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.sacommons.IndexTIFSourceConfigRequest;

import java.io.IOException;
import java.util.List;

/**
 * Threat intel feed config creation request
 */
public class SAIndexTIFSourceConfigRequest extends ActionRequest implements IndexTIFSourceConfigRequest {
    private static final SourceConfigDtoValidator VALIDATOR = new SourceConfigDtoValidator();
    private String tifSourceConfigId;
    private final RestRequest.Method method;
    private SATIFSourceConfigDto saTifSourceConfigDto;

    public SAIndexTIFSourceConfigRequest(String tifSourceConfigId,
                                         RestRequest.Method method,
                                         SATIFSourceConfigDto saTifSourceConfigDto) {
        super();
        this.tifSourceConfigId = tifSourceConfigId;
        this.method = method;
        this.saTifSourceConfigDto = saTifSourceConfigDto;
    }

    public SAIndexTIFSourceConfigRequest(StreamInput sin) throws IOException {
        this(
                sin.readString(), // tif config id
                sin.readEnum(RestRequest.Method.class), // method
                SATIFSourceConfigDto.readFrom(sin) // SA tif config dto
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(tifSourceConfigId);
        out.writeEnum(method);
        saTifSourceConfigDto.writeTo(out);
    }

    @Override
    public String getTIFConfigId() {
        return tifSourceConfigId;
    }

    public void setTIFConfigId(String tifConfigId) {
        this.tifSourceConfigId = tifConfigId;
    }

    @Override
    public SATIFSourceConfigDto getTIFConfigDto() {
        return saTifSourceConfigDto;
    }

    public void setTIFConfigDto(SATIFSourceConfigDto saTifSourceConfigDto) {
        this.saTifSourceConfigDto = saTifSourceConfigDto;
    }

    public RestRequest.Method getMethod() {
        return method;
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException errors = new ActionRequestValidationException();
        List<String> errorMsgs = VALIDATOR.validateSourceConfigDto(saTifSourceConfigDto);
        if (errorMsgs.isEmpty() == false) {
            errorMsgs.forEach(errors::addValidationError);
        }
        return errors.validationErrors().isEmpty() ? null : errors;
    }

}
