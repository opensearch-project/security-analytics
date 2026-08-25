/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.regex.Pattern;

public class SigmaCIDRExpression implements SigmaType {
    private static final Pattern PREFIX_PATTERN = Pattern.compile("\\d+");
    private static final Pattern IPV4_PATTERN = Pattern
            .compile("((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)");
    private String cidr;

    public SigmaCIDRExpression(String cidr) throws SigmaTypeError {
        this.cidr = normalizeCidr(cidr);

        if (this.cidr == null) {
            throw new SigmaTypeError("Invalid CIDR expression");
        }
    }

    public String convert() {
        return this.cidr;
    }

    private static String normalizeCidr(String cidr) {
        if (cidr == null) {
            return null;
        }

        String[] values = cidr.split("/", -1);
        if (values.length == 0 || values.length > 2) {
            return null;
        }

        String ip = values[0];
        InetAddress address = parseIpLiteral(ip);
        if (address == null) {
            return null;
        }

        if (values.length == 1) {
            return cidr;
        }

        String prefixStr = values[1];
        if (!PREFIX_PATTERN.matcher(prefixStr).matches()) {
            return null;
        }

        int prefix = Integer.parseInt(prefixStr);
        byte[] addressBytes = address.getAddress();
        if (prefix > addressBytes.length * 8) {
            return null;
        }

        byte[] networkBytes = maskHostBits(addressBytes, prefix);
        if (Arrays.equals(addressBytes, networkBytes)) {
            return cidr;
        }
        try {
            String networkIp = InetAddress.getByAddress(networkBytes).getHostAddress();
            return networkIp + "/" + prefix;
        } catch (UnknownHostException e) {
            return null;
        }
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

    private static byte[] maskHostBits(byte[] address, int prefix) {
        byte[] result = address.clone();
        int hostBits = address.length * 8 - prefix;
        int fullHostBytes = hostBits / 8;
        for (int i = 0; i < fullHostBytes; i++) {
            result[result.length - 1 - i] = 0;
        }
        int partialHostBits = hostBits % 8;
        if (partialHostBits > 0) {
            int idx = result.length - 1 - fullHostBytes;
            result[idx] = (byte) (result[idx] & (0xFF << partialHostBits));
        }
        return result;
    }

    public String getCidr() {
        return cidr;
    }
}
