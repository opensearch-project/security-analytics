/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.action;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.ParseField;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.xcontent.ObjectParser;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.threatIntel.common.TIFMetadata;
import org.opensearch.securityanalytics.threatIntel.common.ParameterValidator;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Locale;

/**
 * threat intel tif job update request
 */
public class UpdateTIFJobRequest extends ActionRequest {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);
    public static final ParseField UPDATE_INTERVAL_IN_DAYS_FIELD = new ParseField("update_interval_in_days");
    private static final ParameterValidator VALIDATOR = new ParameterValidator();

    /**
     * @param name the tif job name
     * @return the tif job name
     */
    private String name;

    /**
     * @param updateInterval update interval of a tif job
     * @return update interval of a tif job
     */
    private TimeValue updateInterval;

    /**
     * Parser of a tif job
     */
    public static final ObjectParser<UpdateTIFJobRequest, Void> PARSER;
    static {
        PARSER = new ObjectParser<>("update_tifjob");
        PARSER.declareLong((request, val) -> request.setUpdateInterval(TimeValue.timeValueDays(val)), UPDATE_INTERVAL_IN_DAYS_FIELD);
    }

    public String getName() {
        return name;
    }

    public TimeValue getUpdateInterval() {
        return updateInterval;
    }

    private void setUpdateInterval(TimeValue updateInterval){
        this.updateInterval = updateInterval;
    }

    /**
     * Constructor
     * @param name name of a tif job
     */
    public UpdateTIFJobRequest(final String name) {
        this.name = name;
    }

    /**
     * Constructor
     * @param in the stream input
     * @throws IOException IOException
     */
    public UpdateTIFJobRequest(final StreamInput in) throws IOException {
        super(in);
        this.name = in.readString();
        this.updateInterval = in.readOptionalTimeValue();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(name);
        out.writeOptionalTimeValue(updateInterval);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException errors = new ActionRequestValidationException();
        if (VALIDATOR.validateTIFJobName(name).isEmpty() == false) {
            errors.addValidationError("no such tif job exist");
        }
        if (updateInterval == null) {
            errors.addValidationError("no values to update");
        }

        validateUpdateInterval(errors);

        return errors.validationErrors().isEmpty() ? null : errors;
    }

    /**
     * Validate updateInterval is equal or larger than 1
     *
     * @param errors the errors to add error messages
     */
    private void validateUpdateInterval(final ActionRequestValidationException errors) {
        if (updateInterval == null) {
            return;
        }

        if (updateInterval.compareTo(TimeValue.timeValueDays(1)) < 0) {
            errors.addValidationError("Update interval should be equal to or larger than 1 day");
        }
    }
}
