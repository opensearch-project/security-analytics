/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.action;

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
import org.opensearch.securityanalytics.threatintel.common.DatasourceManifest;
import org.opensearch.securityanalytics.threatintel.common.ParameterValidator;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Locale;

/**
 * threat intel datasource update request
 */
public class UpdateDatasourceRequest extends ActionRequest {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    public static final ParseField ENDPOINT_FIELD = new ParseField("endpoint");
    public static final ParseField UPDATE_INTERVAL_IN_DAYS_FIELD = new ParseField("update_interval_in_days");
    private static final int MAX_DATASOURCE_NAME_BYTES = 255;
    private static final ParameterValidator VALIDATOR = new ParameterValidator();

    /**
     * @param name the datasource name
     * @return the datasource name
     */
    private String name;
    /**
     * @param endpoint url to a manifest file for a datasource
     * @return url to a manifest file for a datasource
     */
    private String endpoint;
    /**
     * @param updateInterval update interval of a datasource
     * @return update interval of a datasource
     */
    private TimeValue updateInterval;

    /**
     * Parser of a datasource
     */
    public static final ObjectParser<UpdateDatasourceRequest, Void> PARSER;
    static {
        PARSER = new ObjectParser<>("update_datasource");
        PARSER.declareString((request, val) -> request.setEndpoint(val), ENDPOINT_FIELD);
        PARSER.declareLong((request, val) -> request.setUpdateInterval(TimeValue.timeValueDays(val)), UPDATE_INTERVAL_IN_DAYS_FIELD);
    }

    private void setEndpoint(String val) {

    }

    /**
     * Constructor
     * @param name name of a datasource
     */
    public UpdateDatasourceRequest(final String name) {
        this.name = name;
    }

    /**
     * Constructor
     * @param in the stream input
     * @throws IOException IOException
     */
    public UpdateDatasourceRequest(final StreamInput in) throws IOException {
        super(in);
        this.name = in.readString();
        this.endpoint = in.readOptionalString();
        this.updateInterval = in.readOptionalTimeValue();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(name);
        out.writeOptionalString(endpoint);
        out.writeOptionalTimeValue(updateInterval);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException errors = new ActionRequestValidationException();
        if (VALIDATOR.validateDatasourceName(name).isEmpty() == false) {
            errors.addValidationError("no such datasource exist");
        }
        if (endpoint == null && updateInterval == null) {
            errors.addValidationError("no values to update");
        }

        validateEndpoint(errors);
        validateUpdateInterval(errors);

        return errors.validationErrors().isEmpty() ? null : errors;
    }

    /**
     * Conduct following validation on endpoint
     * 1. endpoint format complies with RFC-2396
     * 2. validate manifest file from the endpoint
     *
     * @param errors the errors to add error messages
     */
    private void validateEndpoint(final ActionRequestValidationException errors) {
        if (endpoint == null) {
            return;
        }

        try {
            URL url = new URL(endpoint);
            url.toURI(); // Validate URL complies with RFC-2396
            validateManifestFile(url, errors);
        } catch (MalformedURLException | URISyntaxException e) {
            log.info("Invalid URL[{}] is provided", endpoint, e);
            errors.addValidationError("Invalid URL format is provided");
        }
    }

    /**
     * Conduct following validation on url
     * 1. can read manifest file from the endpoint
     * 2. the url in the manifest file complies with RFC-2396
     *
     * @param url the url to validate
     * @param errors the errors to add error messages
     */
    private void validateManifestFile(final URL url, final ActionRequestValidationException errors) {
        DatasourceManifest manifest;
        try {
            manifest = DatasourceManifest.Builder.build(url);
        } catch (Exception e) {
            log.info("Error occurred while reading a file from {}", url, e);
            errors.addValidationError(String.format(Locale.ROOT, "Error occurred while reading a file from %s: %s", url, e.getMessage()));
            return;
        }

        try {
            new URL(manifest.getUrl()).toURI(); // Validate URL complies with RFC-2396
        } catch (MalformedURLException | URISyntaxException e) {
            log.info("Invalid URL[{}] is provided for url field in the manifest file", manifest.getUrl(), e);
            errors.addValidationError("Invalid URL format is provided for url field in the manifest file");
        }
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
