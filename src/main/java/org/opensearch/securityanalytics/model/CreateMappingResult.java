/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

import java.util.Map;
import org.opensearch.action.support.master.AcknowledgedResponse;

public class CreateMappingResult {

    private AcknowledgedResponse acknowledgedResponse;
    private String concreteIndexName;
    private Map<String, Object> mappings;
    private String errorMessage;
    private Exception exception;

    public CreateMappingResult() {}

    public CreateMappingResult(AcknowledgedResponse acknowledgedResponse, String concreteIndexName, Map<String, Object> mappingsSource, String errorMessage, Exception exception) {
        this.acknowledgedResponse = acknowledgedResponse;
        this.concreteIndexName = concreteIndexName;
        this.mappings = mappingsSource;
        this.errorMessage = errorMessage;
        this.exception = exception;
    }

    public CreateMappingResult(AcknowledgedResponse acknowledgedResponse, String concreteIndexName, Map<String, Object> mappingsSource) {
        this.acknowledgedResponse = acknowledgedResponse;
        this.concreteIndexName = concreteIndexName;
        this.mappings = mappingsSource;
    }

    public AcknowledgedResponse getAcknowledgedResponse() {
        return acknowledgedResponse;
    }

    public void setAcknowledgedResponse(AcknowledgedResponse acknowledgedResponse) {
        this.acknowledgedResponse = acknowledgedResponse;
    }

    public String getConcreteIndexName() {
        return concreteIndexName;
    }

    public void setConcreteIndexName(String concreteIndexName) {
        this.concreteIndexName = concreteIndexName;
    }

    public Map<String, Object> getMappings() {
        return mappings;
    }

    public void setMappings(Map<String, Object> mappings) {
        this.mappings = this.mappings;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public Exception getException() {
        return exception;
    }

    public void setException(Exception exception) {
        this.exception = exception;
    }
}
