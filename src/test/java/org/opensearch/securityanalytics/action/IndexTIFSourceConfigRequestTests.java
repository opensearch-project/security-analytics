/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.junit.Assert;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.rest.RestRequest;
import org.opensearch.securityanalytics.threatIntel.action.SAIndexTIFSourceConfigRequest;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import static org.opensearch.securityanalytics.TestHelpers.randomSATIFSourceConfigDto;

public class IndexTIFSourceConfigRequestTests extends OpenSearchTestCase {

    public void testTIFSourceConfigPostRequest() throws IOException {
        SATIFSourceConfigDto saTifSourceConfigDto = randomSATIFSourceConfigDto();
        String id = saTifSourceConfigDto.getId();
        SAIndexTIFSourceConfigRequest request = new SAIndexTIFSourceConfigRequest(id, RestRequest.Method.POST, saTifSourceConfigDto);
        Assert.assertNotNull(request);

        BytesStreamOutput out = new BytesStreamOutput();
        request.writeTo(out);

        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        SAIndexTIFSourceConfigRequest newRequest = new SAIndexTIFSourceConfigRequest(sin);
        Assert.assertEquals(id, request.getTIFConfigId());
        Assert.assertEquals(RestRequest.Method.POST, newRequest.getMethod());
        Assert.assertNotNull(newRequest.getTIFConfigDto());
    }

    public void testValidateSourceConfigPostRequest() {
        // Source config with invalid: name, format, source, ioc type, source config type
        SATIFSourceConfigDto saTifSourceConfigDto = new SATIFSourceConfigDto(
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                false,
                null,
                true,
                null
        );
        String id = saTifSourceConfigDto.getId();
        SAIndexTIFSourceConfigRequest request = new SAIndexTIFSourceConfigRequest(id, RestRequest.Method.POST, saTifSourceConfigDto);
        Assert.assertNotNull(request);

        ActionRequestValidationException exception = request.validate();
        assertEquals(4, exception.validationErrors().size());
        assertTrue(exception.validationErrors().contains("Name must not be empty"));
        assertTrue(exception.validationErrors().contains("Format must not be empty"));
        assertTrue(exception.validationErrors().contains("Source must not be empty"));
        assertTrue(exception.validationErrors().contains("Type must not be empty"));
    }
}