/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SigmaCIDRExpression implements SigmaType {
    private String cidr;

    public SigmaCIDRExpression(String cidr) throws SigmaTypeError {
        this.cidr = cidr;

        if (!isIPv4AddressValid(this.cidr)) {
            throw new SigmaTypeError("Invalid IPv4 CIDR expression");
        }
    }

    public String convert() {
        return this.cidr;
    }

    private static boolean isIPv4AddressValid(String cidr) {
        if (cidr == null) {
            return false;
        }

        String[] values = cidr.split("/");
        Pattern ipv4Pattern = Pattern
                .compile("(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])");
        Matcher mm = ipv4Pattern.matcher(values[0]);
        if (!mm.matches()) {
            return false;
        }
        if (values.length >= 2) {
            int prefix = Integer.parseInt(values[1]);
            if ((prefix < 0) || (prefix > 32)) {
                return false;
            }
        }
        return true;
    }

    public String getCidr() {
        return cidr;
    }
}