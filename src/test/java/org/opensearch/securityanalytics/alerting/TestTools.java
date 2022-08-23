/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.alerting;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;

public class TestTools {

    private TestTools() {
        // do nothing
    }


    public static String asString(final InputStream stream) {
        try {
            final BufferedReader b = new BufferedReader(new InputStreamReader(stream, Charset.defaultCharset()));
            String temp = "";
            while (b.ready()) {
                temp = temp + "\n" + b.readLine();
            }
            return temp.trim();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static JSONObject asJSON(final InputStream stream) {
        return new JSONObject(asString(stream));
    }

    public static String prettyString(final InputStream stream) {
        return new JSONObject(asString(stream)).toString(4);
    }

}