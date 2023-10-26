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
    private static final int MAX_TIFJOB_NAME_BYTES = 127;

    /**
     * Validate TIF Job name and return list of error messages
     *
     * @param tifJobName tifJobName name
     * @return Error messages. Empty list if there is no violation.
     */
    public List<String> validateTIFJobName(final String tifJobName) {
        List<String> errorMsgs = new ArrayList<>();
        if (StringUtils.isBlank(tifJobName)) {
            errorMsgs.add("threat intel feed job name must not be empty");
            return errorMsgs;
        }

        if (!Strings.validFileName(tifJobName)) {
            errorMsgs.add(
                    String.format(Locale.ROOT, "threat intel feed job name must not contain the following characters %s", Strings.INVALID_FILENAME_CHARS)
            );
        }
        if (tifJobName.contains("#") || tifJobName.contains(":") ) {
            errorMsgs.add("threat intel feed job name must not contain '#'");
        }
        if (tifJobName.charAt(0) == '_' || tifJobName.charAt(0) == '-' || tifJobName.charAt(0) == '+') {
            errorMsgs.add("threat intel feed job name must not start with '_', '-', or '+'");
        }
        int byteCount = tifJobName.getBytes(StandardCharsets.UTF_8).length;
        if (byteCount > MAX_TIFJOB_NAME_BYTES) {
            errorMsgs.add(String.format(Locale.ROOT, "threat intel feed job name is too long, (%d > %d)", byteCount, MAX_TIFJOB_NAME_BYTES));
        }
        if (tifJobName.equals(".") || tifJobName.equals("..")) {
            errorMsgs.add("threat intel feed job name must not be '.' or '..'");
        }
        return errorMsgs;
    }
}