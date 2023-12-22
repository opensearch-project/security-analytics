///*
// * Copyright OpenSearch Contributors
// * SPDX-License-Identifier: Apache-2.0
// */
//
//package org.opensearch.securityanalytics.threatIntel.action;
//
//import org.opensearch.action.ActionRequest;
//import org.opensearch.action.ActionRequestValidationException;
//import org.opensearch.common.unit.TimeValue;
//import org.opensearch.core.common.io.stream.StreamInput;
//import org.opensearch.core.common.io.stream.StreamOutput;
//import org.opensearch.securityanalytics.threatIntel.common.ParameterValidator;
//
//import java.io.IOException;
//import java.util.List;
//
///**
// * Threat intel tif job creation request
// */
//public class PutTIFJobRequest extends ActionRequest {
//    private static final ParameterValidator VALIDATOR = new ParameterValidator();
//
//    /**
//     * @param name the tif job name
//     * @return the tif job name
//     */
//    private String name;
//
//    /**
//     * @param updateInterval update interval of a tif job
//     * @return update interval of a tif job
//     */
//    private TimeValue updateInterval;
//
//    public void setName(String name) {
//        this.name = name;
//    }
//
//    public String getName() {
//        return name;
//    }
//
//    public TimeValue getUpdateInterval() {
//        return this.updateInterval;
//    }
//
//    /**
//     * Default constructor
//     * @param name name of a tif job
//     */
//    public PutTIFJobRequest(final String name, final TimeValue updateInterval) {
//        this.name = name;
//        this.updateInterval = updateInterval;
//    }
//
//    /**
//     * Constructor with stream input
//     * @param in the stream input
//     * @throws IOException IOException
//     */
//    public PutTIFJobRequest(final StreamInput in) throws IOException {
//        super(in);
//        this.name = in.readString();
//        this.updateInterval = in.readTimeValue();
//    }
//
//    @Override
//    public void writeTo(final StreamOutput out) throws IOException {
//        super.writeTo(out);
//        out.writeString(name);
//        out.writeTimeValue(updateInterval);
//    }
//
//    @Override
//    public ActionRequestValidationException validate() {
//        ActionRequestValidationException errors = new ActionRequestValidationException();
//        List<String> errorMsgs = VALIDATOR.validateTIFJobName(name);
//        if (errorMsgs.isEmpty() == false) {
//            errorMsgs.stream().forEach(msg -> errors.addValidationError(msg));
//        }
//        return errors.validationErrors().isEmpty() ? null : errors;
//    }
//
//}
