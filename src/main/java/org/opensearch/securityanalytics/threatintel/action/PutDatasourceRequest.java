/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatintel.action;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Locale;

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

/**
 * Threat intel datasource creation request
 */
public class PutDatasourceRequest extends ActionRequest {
    private static final Logger log = LogManager.getLogger(DetectorTrigger.class);

    public static final ParseField FEED_FORMAT_FIELD = new ParseField("feed_format");
    public static final ParseField ENDPOINT_FIELD = new ParseField("endpoint");
    public static final ParseField FEED_NAME_FIELD = new ParseField("feed_name");
    public static final ParseField DESCRIPTION_FIELD = new ParseField("description");
    public static final ParseField ORGANIZATION_FIELD = new ParseField("organization");
    public static final ParseField CONTAINED_IOCS_FIELD = new ParseField("contained_iocs_field");
    public static final ParseField UPDATE_INTERVAL_IN_DAYS_FIELD = new ParseField("update_interval_in_days");
    private static final ParameterValidator VALIDATOR = new ParameterValidator();

    /**
     * @param name the datasource name
     * @return the datasource name
     */
    private String name;

    private String feedFormat;

    /**
     * @param endpoint url to a manifest file for a datasource
     * @return url to a manifest file for a datasource
     */
    private String endpoint;

    private String feedName;

    private String description;

    private String organization;

    private List<String> contained_iocs_field;

    /**
     * @param updateInterval update interval of a datasource
     * @return update interval of a datasource
     */
    private TimeValue updateInterval;

    /**
     * Parser of a datasource
     */
    public static final ObjectParser<PutDatasourceRequest, Void> PARSER;
    static {
        PARSER = new ObjectParser<>("put_datasource");
        PARSER.declareString((request, val) -> request.setFeedFormat(val), FEED_FORMAT_FIELD);
        PARSER.declareString((request, val) -> request.setEndpoint(val), ENDPOINT_FIELD);
        PARSER.declareString((request, val) -> request.setFeedName(val), FEED_NAME_FIELD);
        PARSER.declareString((request, val) -> request.setDescription(val), DESCRIPTION_FIELD);
        PARSER.declareString((request, val) -> request.setOrganization(val), ORGANIZATION_FIELD);
//        PARSER.declareStringArray((request, val[]) -> request.setContained_iocs_field(val), CONTAINED_IOCS_FIELD);
        PARSER.declareLong((request, val) -> request.setUpdateInterval(TimeValue.timeValueDays(val)), UPDATE_INTERVAL_IN_DAYS_FIELD);
    }

    /**
     * Default constructor
     * @param name name of a datasource
     */
    public PutDatasourceRequest(final String name) {
        this.name = name;
    }

    /**
     * Constructor with stream input
     * @param in the stream input
     * @throws IOException IOException
     */
    public PutDatasourceRequest(final StreamInput in) throws IOException {
        super(in);
        this.name = in.readString();
        this.feedFormat = in.readString();
        this.endpoint = in.readString();
        this.feedName = in.readString();
        this.description = in.readString();
        this.organization = in.readString();
        this.contained_iocs_field = in.readStringList();
        this.updateInterval = in.readTimeValue();
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeString(name);
        out.writeString(feedFormat);
        out.writeString(endpoint);
        out.writeString(feedName);
        out.writeString(description);
        out.writeString(organization);
        out.writeStringCollection(contained_iocs_field);
        out.writeTimeValue(updateInterval);
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException errors = new ActionRequestValidationException();
        List<String> errorMsgs = VALIDATOR.validateDatasourceName(name);
        if (errorMsgs.isEmpty() == false) {
            errorMsgs.stream().forEach(msg -> errors.addValidationError(msg));
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
     * 3. updateInterval is less than validForInDays value in the manifest file
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
            return;
        }

//        if (manifest.getValidForInDays() != null && updateInterval.days() >= manifest.getValidForInDays()) {
//            errors.addValidationError(
//                    String.format(
//                            Locale.ROOT,
//                            "updateInterval %d should be smaller than %d",
//                            updateInterval.days(),
//                            manifest.getValidForInDays()
//                    )
//            );
//        }
    }

    /**
     * Validate updateInterval is equal or larger than 1
     *
     * @param errors the errors to add error messages
     */
    private void validateUpdateInterval(final ActionRequestValidationException errors) {
        if (updateInterval.compareTo(TimeValue.timeValueDays(1)) < 0) {
            errors.addValidationError("Update interval should be equal to or larger than 1 day");
        }
    }

    public String getName() {
        return name;
    }

    public String getEndpoint() {
        return this.endpoint;
    }

    public void setEndpoint(String newEndpoint) {
        this.endpoint = newEndpoint;
    }

    public TimeValue getUpdateInterval() {
        return this.updateInterval;
    }

    public void setUpdateInterval(TimeValue timeValue) {
        this.updateInterval = timeValue;
    }
}
