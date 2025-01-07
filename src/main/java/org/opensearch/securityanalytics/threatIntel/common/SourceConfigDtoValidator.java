/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.common;

import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.threatIntel.model.CustomSchemaIocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.IocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.model.UrlDownloadSource;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.apache.logging.log4j.util.Strings.isBlank;

/**
 * Source config dto validator
 */
public class SourceConfigDtoValidator {
    public List<String> validateSourceConfigDto(SATIFSourceConfigDto sourceConfigDto) {
        List<String> errorMsgs = new ArrayList<>();

        String nameRegex = "^[a-zA-Z0-9 _-]{1,128}$";
        Pattern namePattern = Pattern.compile(nameRegex);

        int MAX_RULE_DESCRIPTION_LENGTH = 65535;
        String descriptionRegex = "^.{0," + MAX_RULE_DESCRIPTION_LENGTH + "}$";
        Pattern descriptionPattern = Pattern.compile(descriptionRegex);

        if (sourceConfigDto.getName() == null || sourceConfigDto.getName().isEmpty()) {
            errorMsgs.add("Name must not be empty");
        } else if (sourceConfigDto.getName() != null && namePattern.matcher(sourceConfigDto.getName()).matches() == false) {
            errorMsgs.add("Name must be less than 128 characters and only consist of upper and lowercase letters, numbers 0-9, hyphens, spaces, and underscores");
        }

        if (sourceConfigDto.getFormat() == null || sourceConfigDto.getFormat().isEmpty()) {
            errorMsgs.add("Format must not be empty");
        } else if (sourceConfigDto.getFormat() != null && sourceConfigDto.getFormat().length() > 50) {
            errorMsgs.add("Format must be 50 characters or less");
        }

        if (sourceConfigDto.getDescription() != null && descriptionPattern.matcher(sourceConfigDto.getDescription()).matches() == false) {
            errorMsgs.add("Description must be " + MAX_RULE_DESCRIPTION_LENGTH + " characters or less");
        }

        if (sourceConfigDto.getSource() == null) {
            errorMsgs.add("Source must not be empty");
        }

        if (sourceConfigDto.getIocTypes() == null || sourceConfigDto.getIocTypes().isEmpty()) {
            errorMsgs.add("Must specify at least one IOC type");
        } else {
            for (String s: sourceConfigDto.getIocTypes()) {
                if (!IOCType.supportedType(s)) {
                    errorMsgs.add("Invalid IOC type: " + s);
                }
            }
        }

        if (sourceConfigDto.getType() == null) {
            errorMsgs.add("Type must not be empty");
        } else {
            switch (sourceConfigDto.getType()) {
                case IOC_UPLOAD:
                    if (sourceConfigDto.isEnabled()) {
                        errorMsgs.add("Job Scheduler cannot be enabled for IOC_UPLOAD type");
                    }
                    if (sourceConfigDto.getSchedule() != null) {
                        errorMsgs.add("Cannot pass in schedule for IOC_UPLOAD type");
                    }
                    if (sourceConfigDto.getSource() != null && sourceConfigDto.getSource() instanceof IocUploadSource == false) {
                        errorMsgs.add("Source must be IOC_UPLOAD type");
                    }
                    if (sourceConfigDto.getSource() instanceof IocUploadSource && ((IocUploadSource) sourceConfigDto.getSource()).getIocs() == null) {
                        errorMsgs.add("Ioc list must include at least one ioc");
                    }
                    break;
                case CUSTOM_SCHEMA_IOC_UPLOAD:
                    if (sourceConfigDto.isEnabled()) {
                        errorMsgs.add("Job Scheduler cannot be enabled for CUSTOM_SCHEMA_IOC_UPLOAD type");
                    }
                    if (sourceConfigDto.getSchedule() != null) {
                        errorMsgs.add("Cannot pass in schedule for CUSTOM_SCHEMA_IOC_UPLOAD type");
                    }
                    if (sourceConfigDto.getSource() != null && sourceConfigDto.getSource() instanceof CustomSchemaIocUploadSource == false) {
                        errorMsgs.add("Source must be CUSTOM_SCHEMA_IOC_UPLOAD type");
                    }
                    if (sourceConfigDto.getSource() instanceof CustomSchemaIocUploadSource &&
                            isBlank(((CustomSchemaIocUploadSource) sourceConfigDto.getSource()).getIocs())
                    ) {
                        errorMsgs.add("Ioc list must include at least one ioc");
                    }
                    // TODO validate the iocs are in format defined in schema
                    break;
                case S3_CUSTOM:
                    if (sourceConfigDto.getSchedule() == null) {
                        errorMsgs.add("Must pass in schedule for S3_CUSTOM type");
                    }
                    if (sourceConfigDto.getSource() != null && sourceConfigDto.getSource() instanceof S3Source == false) {
                        errorMsgs.add("Source must be S3_CUSTOM type");
                    }
                    break;
                case URL_DOWNLOAD:
                    if (sourceConfigDto.getSchedule() == null) {
                        errorMsgs.add("Must pass in schedule for URL_DOWNLOAD source type");
                    }
                    if (sourceConfigDto.getSource() != null && sourceConfigDto.getSource() instanceof UrlDownloadSource == false) {
                        errorMsgs.add("Source must be URL_DOWNLOAD source type");
                    }
                    break;
            }
        }
        return errorMsgs;
    }
}