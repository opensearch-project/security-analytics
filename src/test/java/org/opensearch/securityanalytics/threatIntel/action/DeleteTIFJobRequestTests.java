/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.BytesStreamInput;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestHelper;

import java.io.IOException;

public class DeleteTIFJobRequestTests extends ThreatIntelTestCase {

    public void testStreamInOut_whenValidInput_thenSucceed() throws IOException {
        String tifJobParameterName = ThreatIntelTestHelper.randomLowerCaseString();
        DeleteTIFJobRequest request = new DeleteTIFJobRequest(tifJobParameterName);

        // Run
        BytesStreamOutput output = new BytesStreamOutput();
        request.writeTo(output);
        BytesStreamInput input = new BytesStreamInput(output.bytes().toBytesRef().bytes);
        DeleteTIFJobRequest copiedRequest = new DeleteTIFJobRequest(input);

        // Verify
        assertEquals(request.getName(), copiedRequest.getName());
    }

    public void testValidate_whenNull_thenError() {
        DeleteTIFJobRequest request = new DeleteTIFJobRequest((String) null);

        // Run
        ActionRequestValidationException error = request.validate();

        // Verify
        assertNotNull(error.validationErrors());
        assertFalse(error.validationErrors().isEmpty());
    }

    public void testValidate_whenBlank_thenError() {
        DeleteTIFJobRequest request = new DeleteTIFJobRequest(" ");

        // Run
        ActionRequestValidationException error = request.validate();

        // Verify
        assertNotNull(error.validationErrors());
        assertFalse(error.validationErrors().isEmpty());
    }

    public void testValidate_whenInvalidTIFJobParameterName_thenFails() {
        String invalidName = "_" + ThreatIntelTestHelper.randomLowerCaseString();
        DeleteTIFJobRequest request = new DeleteTIFJobRequest(invalidName);

        // Run
        ActionRequestValidationException exception = request.validate();

        // Verify
        assertEquals(1, exception.validationErrors().size());
        assertTrue(exception.validationErrors().get(0).contains("no such job exists"));
    }
}
