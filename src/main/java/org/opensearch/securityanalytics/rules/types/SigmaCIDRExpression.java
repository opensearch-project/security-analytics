/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;

import java.net.Inet6Address;
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

        // Intentional leniency: bare IPs without a prefix and CIDRs with host bits
        // set are accepted and stored verbatim, matching the historical behavior.
        String[] values = cidr.split("/", -1);
        if (values.length > 2) {
            return false;
        }

        String ip = values[0];
        if (parseIpLiteral(ip) == null) {
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
        int maxPrefix = ip.indexOf(':') < 0 ? 32 : 128;
        return prefix <= maxPrefix;
    }

    private static InetAddress parseIpLiteral(String ip) {
        if (ip.indexOf('%') >= 0) {
            return null;
        }
        // A string containing ':' can only be an IPv6 literal; hostnames cannot contain
        // ':', so getByName never triggers DNS resolution. IPv4-mapped literals such as
        // ::ffff:1.2.3.4 are treated as IPv6 here (max prefix 128) regardless of the
        // InetAddress Java happens to return.
        if (ip.indexOf(':') >= 0) {
            try {
                return Inet6Address.getByName(ip);
            } catch (UnknownHostException e) {
                return null;
            }
        }
        if (!IPV4_PATTERN.matcher(ip).matches()) {
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
