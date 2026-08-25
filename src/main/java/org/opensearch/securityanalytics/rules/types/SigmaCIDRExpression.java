/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

public class SigmaCIDRExpression implements SigmaType {
    private static final Pattern PREFIX_PATTERN = Pattern.compile("\\d+");
    private String cidr;

    public SigmaCIDRExpression(String cidr) throws SigmaTypeError {
        this.cidr = cidr;

        if (!isValidCidr(this.cidr)) {
            throw new SigmaTypeError("Invalid CIDR expression");
        }
    }

    public String convert() {
        return this.cidr;
    }

    private static boolean isValidCidr(String cidr) {
        if (cidr == null) {
            return false;
        }

        String[] values = cidr.split("/", -1);
        if (values.length == 0 || values.length > 2) {
            return false;
        }

        InetAddress address;
        try {
            address = InetAddress.getByName(values[0]);
        } catch (UnknownHostException e) {
            return false;
        }

        if (values.length == 1) {
            return true;
        }

        String prefixStr = values[1];
        if (!PREFIX_PATTERN.matcher(prefixStr).matches()) {
            return false;
        }

        int prefix = Integer.parseInt(prefixStr);
        int maxPrefix = address instanceof Inet4Address ? 32 : 128;
        return prefix <= maxPrefix;
    }

    public String getCidr() {
        return cidr;
    }
}
