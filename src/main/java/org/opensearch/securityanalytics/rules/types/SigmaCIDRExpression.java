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
        byte[] addressBytes = address.getAddress();
        if (prefix > addressBytes.length * 8) {
            return false;
        }
        return isCanonicalNetworkAddress(addressBytes, prefix);
    }

    private static InetAddress parseIpLiteral(String ip) {
        // Only a string matching an IPv4 literal or containing ':' can be a valid IP
        // literal; hostnames satisfy neither, so getByName never triggers DNS resolution.
        if (!IPV4_PATTERN.matcher(ip).matches() && ip.indexOf(':') < 0) {
            return null;
        }
        try {
            return InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static boolean isCanonicalNetworkAddress(byte[] address, int prefix) {
        int hostBits = address.length * 8 - prefix;
        if (hostBits == 0) {
            return true;
        }

        int fullHostBytes = hostBits / 8;
        for (int i = 0; i < fullHostBytes; i++) {
            if (address[address.length - 1 - i] != 0) {
                return false;
            }
        }

        int partialHostBits = hostBits % 8;
        if (partialHostBits > 0) {
            int idx = address.length - 1 - fullHostBytes;
            int value = address[idx] & 0xFF;
            if ((value & (0xFF << partialHostBits)) != value) {
                return false;
            }
        }
        return true;
    }

    public String getCidr() {
        return cidr;
    }
}
