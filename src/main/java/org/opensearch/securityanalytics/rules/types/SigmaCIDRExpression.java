/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

public class SigmaCIDRExpression implements SigmaType {
    private static final Pattern PREFIX_PATTERN = Pattern.compile("\\d+");
    private static final Pattern IPV4_PATTERN = Pattern
            .compile("((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)");
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

        String ip = values[0];
        InetAddress address = parseIpLiteral(ip);
        if (address == null) {
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
        return prefix <= address.getAddress().length * 8;
    }

    private static InetAddress parseIpLiteral(String ip) {
        // Only a string matching an IPv4 literal or containing ':' can be a valid IP
        // literal; hostnames satisfy neither, so getByName never triggers DNS resolution.
        if (ip.indexOf('%') >= 0) {
            return null;
        }
        if (!IPV4_PATTERN.matcher(ip).matches() && ip.indexOf(':') < 0) {
            return null;
        }
        try {
            return InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    public String getCidr() {
        return cidr;
    }
}
