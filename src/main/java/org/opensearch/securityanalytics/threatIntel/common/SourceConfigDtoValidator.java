/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.common;

import org.opensearch.securityanalytics.commons.model.IOC;
import org.opensearch.securityanalytics.commons.model.IOCType;
import org.opensearch.securityanalytics.threatIntel.model.IocUploadSource;
import org.opensearch.securityanalytics.threatIntel.model.S3Source;
import org.opensearch.securityanalytics.threatIntel.model.SATIFSourceConfigDto;
import org.opensearch.securityanalytics.threatIntel.model.UrlDownloadSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Source config dto validator
 */
public class SourceConfigDtoValidator {
    public List<String> validateSourceConfigDto(SATIFSourceConfigDto sourceConfigDto) {
        List<String> errorMsgs = new ArrayList<>();

        if (sourceConfigDto.getIocTypes().isEmpty()) {
            errorMsgs.add("Must specify at least one IOC type");
        } else {
            for (String s: sourceConfigDto.getIocTypes()) {
                if (!IOCType.supportedType(s)) {
                    errorMsgs.add("Invalid IOC type: " + s);
                }
            }
        }

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
        return errorMsgs;
    }
}