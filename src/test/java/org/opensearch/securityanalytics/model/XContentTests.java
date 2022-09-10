/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.junit.Assert;

import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.commons.authuser.User;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import static org.opensearch.securityanalytics.TestHelpers.*;

public class XContentTests extends OpenSearchTestCase {

    public void testDetectorParsing() throws IOException {
        Detector detector = randomDetector();

        String detectorString = toJsonStringWithUser(detector);
        Detector parsedDetector = Detector.parse(parser(detectorString), null, null);
        Assert.assertEquals("Round tripping Detector doesn't work", detector, parsedDetector);
    }

    public void testDetectorParsingWithNoName() {
        String detectorStringWithoutName = "{\n" +
                "  \"type\": \"detector\",\n" +
                "  \"detector_type\": \"windows\",\n" +
                "  \"enabled\": true,\n" +
                "  \"createdBy\": \"chip\",\n" +
                "  \"schedule\": {\n" +
                "    \"period\": {\n" +
                "      \"interval\": 1,\n" +
                "      \"unit\": \"MINUTES\"\n" +
                "    }\n" +
                "  },\n" +
                "  \"inputs\": [    {\n" +
                "      \"input\": {\n" +
                "        \"description\": \"windows detector for security analytics\",\n" +
                "        \"indices\": [\n" +
                "          \"windows\"\n" +
                "        ],\n" +
                "        \"rules\": []\n" +
                "      }\n" +
                "    }\n" +
                "\n" +
                "  ]\n" +
                "}";

        Exception exception = assertThrows(NullPointerException.class, () -> {
            Detector.parse(parser(detectorStringWithoutName), null, null);
        });

        String expectedMessage = "Detector name is null";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testDetectorParsingWithNoSchedule() {
        String detectorStringWithoutSchedule = "{\n" +
                "  \"type\": \"detector\",\n" +
                "  \"detector_type\": \"windows\",\n" +
                "  \"name\": \"windows_detector\",\n" +
                "  \"enabled\": true,\n" +
                "  \"createdBy\": \"chip\",\n" +
                "  \"inputs\": [    {\n" +
                "      \"input\": {\n" +
                "        \"description\": \"windows detector for security analytics\",\n" +
                "        \"indices\": [\n" +
                "          \"windows\"\n" +
                "        ],\n" +
                "        \"rules\": []\n" +
                "      }\n" +
                "    }\n" +
                "\n" +
                "  ]\n" +
                "}";

        Exception exception = assertThrows(NullPointerException.class, () -> {
            Detector.parse(parser(detectorStringWithoutSchedule), null, null);
        });

        String expectedMessage = "Detector schedule is null";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testUserParsing() throws IOException {
        User user = randomUser();
        String userString = BytesReference.bytes(user.toXContent(builder(), ToXContent.EMPTY_PARAMS)).utf8ToString();
        User parsedUser = User.parse(parser(userString));

        Assert.assertEquals("Round tripping user doesn't work", user, parsedUser);
    }

    public void testEmptyUserParsing() throws IOException {
        User user = randomUserEmpty();
        String userString = BytesReference.bytes(user.toXContent(builder(), ToXContent.EMPTY_PARAMS)).utf8ToString();
        User parsedUser = User.parse(parser(userString));

        Assert.assertEquals("Round tripping user doesn't work", user, parsedUser);
        Assert.assertEquals("", parsedUser.getName());
        Assert.assertEquals(0, parsedUser.getRoles().size());
    }

    public void testDetectorParsingWithNoUser() throws IOException {
        Detector detector = randomDetectorWithNoUser();

        String detectorString = toJsonStringWithUser(detector);
        Detector parsedDetector = Detector.parse(parser(detectorString), null, null);
        Assert.assertEquals("Round tripping Detector doesn't work", detector, parsedDetector);
    }
}