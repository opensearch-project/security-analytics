/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.junit.Assert;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.commons.authuser.User;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.List;

import static org.opensearch.securityanalytics.TestHelpers.randomDetector;
import static org.opensearch.securityanalytics.TestHelpers.randomUser;
import static org.opensearch.securityanalytics.TestHelpers.randomUserEmpty;

public class WriteableTests extends OpenSearchTestCase {

    public void testDetectorAsStream() throws IOException {
        Detector detector = randomDetector();
        detector.setInputs(List.of(new DetectorInput("", List.of(), List.of())));
        BytesStreamOutput out = new BytesStreamOutput();
        detector.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        Detector newDetector = new Detector(sin);
        Assert.assertEquals("Round tripping Detector doesn't work", detector, newDetector);
    }

    public void testUserAsStream() throws IOException {
        User user = randomUser();
        BytesStreamOutput out = new BytesStreamOutput();
        user.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        User newUser = new User(sin);
        Assert.assertEquals("Round tripping User doesn't work", user, newUser);
    }

    public void testEmptyUserAsStream() throws IOException {
        User user = randomUserEmpty();
        BytesStreamOutput out = new BytesStreamOutput();
        user.writeTo(out);
        StreamInput sin = StreamInput.wrap(out.bytes().toBytesRef().bytes);
        User newUser = new User(sin);
        Assert.assertEquals("Round tripping User doesn't work", user, newUser);
    }
}