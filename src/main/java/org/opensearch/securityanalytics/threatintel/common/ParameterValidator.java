/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.threatIntel.common;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.apache.commons.lang3.StringUtils;
import org.opensearch.core.common.Strings;

/**
 * Parameter validator for TIF APIs
 */
public class ParameterValidator {
    private static final int MAX_DATASOURCE_NAME_BYTES = 127;

    /**
     * Validate datasource name and return list of error messages
     *
     * @param datasourceName datasource name
     * @return Error messages. Empty list if there is no violation.
     */
    public List<String> validateTIFJobName(final String datasourceName) {
        List<String> errorMsgs = new ArrayList<>();
        if (StringUtils.isBlank(datasourceName)) {
            errorMsgs.add("datasource name must not be empty");
            return errorMsgs;
        }

        if (!Strings.validFileName(datasourceName)) {
            errorMsgs.add(
                    String.format(Locale.ROOT, "datasource name must not contain the following characters %s", Strings.INVALID_FILENAME_CHARS)
            );
        }
        if (datasourceName.contains("#")) {
            errorMsgs.add("datasource name must not contain '#'");
        }
        if (datasourceName.contains(":")) {
            errorMsgs.add("datasource name must not contain ':'");
        }
        if (datasourceName.charAt(0) == '_' || datasourceName.charAt(0) == '-' || datasourceName.charAt(0) == '+') {
            errorMsgs.add("datasource name must not start with '_', '-', or '+'");
        }
        int byteCount = datasourceName.getBytes(StandardCharsets.UTF_8).length;
        if (byteCount > MAX_DATASOURCE_NAME_BYTES) {
            errorMsgs.add(String.format(Locale.ROOT, "datasource name is too long, (%d > %d)", byteCount, MAX_DATASOURCE_NAME_BYTES));
        }
        if (datasourceName.equals(".") || datasourceName.equals("..")) {
            errorMsgs.add("datasource name must not be '.' or '..'");
        }
        return errorMsgs;
    }
}
