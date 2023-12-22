///*
// * Copyright OpenSearch Contributors
// * SPDX-License-Identifier: Apache-2.0
// */
//
//package org.opensearch.securityanalytics.threatIntel.action;
//
//import org.opensearch.action.ActionRequestValidationException;
//import org.opensearch.common.io.stream.BytesStreamOutput;
//import org.opensearch.core.common.io.stream.BytesStreamInput;
//import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
//import org.opensearch.securityanalytics.threatIntel.ThreatIntelTestCase;
//import org.opensearch.securityanalytics.TestHelpers;
//
//
//public class PutTIFJobRequestTests extends ThreatIntelTestCase {
//
//    public void testValidate_whenValidInput_thenSucceed() {
//        String tifJobParameterName = TestHelpers.randomLowerCaseString();
//        PutTIFJobRequest request = new PutTIFJobRequest(tifJobParameterName, clusterSettings.get(SecurityAnalyticsSettings.TIF_UPDATE_INTERVAL));
//
//        assertNull(request.validate());
//    }
//
//    public void testValidate_whenInvalidTIFJobParameterName_thenFails() {
//        String invalidName = "_" + TestHelpers.randomLowerCaseString();
//        PutTIFJobRequest request = new PutTIFJobRequest(invalidName, clusterSettings.get(SecurityAnalyticsSettings.TIF_UPDATE_INTERVAL));
//
//        // Run
//        ActionRequestValidationException exception = request.validate();
//
//        // Verify
//        assertEquals(1, exception.validationErrors().size());
//        assertTrue(exception.validationErrors().get(0).contains("must not"));
//    }
//
//    public void testStreamInOut_whenValidInput_thenSucceed() throws Exception {
//        String tifJobParameterName = TestHelpers.randomLowerCaseString();
//        PutTIFJobRequest request = new PutTIFJobRequest(tifJobParameterName, clusterSettings.get(SecurityAnalyticsSettings.TIF_UPDATE_INTERVAL));
//
//        // Run
//        BytesStreamOutput output = new BytesStreamOutput();
//        request.writeTo(output);
//        BytesStreamInput input = new BytesStreamInput(output.bytes().toBytesRef().bytes);
//        PutTIFJobRequest copiedRequest = new PutTIFJobRequest(input);
//
//        // Verify
//        assertEquals(request.getName(), copiedRequest.getName());
//    }
//}
