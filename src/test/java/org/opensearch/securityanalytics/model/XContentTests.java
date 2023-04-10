/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import java.io.IOException;
import java.util.List;
import org.junit.Assert;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.commons.authuser.User;
import org.opensearch.test.OpenSearchTestCase;


import static org.opensearch.securityanalytics.TestHelpers.builder;
import static org.opensearch.securityanalytics.TestHelpers.parser;
import static org.opensearch.securityanalytics.TestHelpers.randomDetector;
import static org.opensearch.securityanalytics.TestHelpers.randomDetectorWithNoUser;
import static org.opensearch.securityanalytics.TestHelpers.randomUser;
import static org.opensearch.securityanalytics.TestHelpers.randomUserEmpty;
import static org.opensearch.securityanalytics.TestHelpers.toJsonStringWithUser;

public class XContentTests extends OpenSearchTestCase {

    public void testDetectorParsing() throws IOException {
        Detector detector = randomDetector(List.of());

        String detectorString = toJsonStringWithUser(detector);
        Detector parsedDetector = Detector.parse(parser(detectorString), null, null);
        Assert.assertEquals("Round tripping Detector doesn't work", detector, parsedDetector);
    }

    public void testDetectorParsingWithNoName() {
        String detectorStringWithoutName = "{\n" +
                "  \"type\": \"detector\",\n" +
                "  \"detector_type\": \"WINDOWS\",\n" +
                "  \"user\": {\n" +
                "    \"name\": \"JPXeGWmlMP\",\n" +
                "    \"backend_roles\": [\n" +
                "      \"lVOjTakxQl\",\n" +
                "      \"rWcHiErFQz\"\n" +
                "    ],\n" +
                "    \"roles\": [\n" +
                "      \"zEMpObrYPM\",\n" +
                "      \"all_access\"\n" +
                "    ],\n" +
                "    \"custom_attribute_names\": [\n" +
                "      \"test_attr=test\"\n" +
                "    ],\n" +
                "    \"user_requested_tenant\": null\n" +
                "  },\n" +
                "  \"enabled\": false,\n" +
                "  \"enabled_time\": null,\n" +
                "  \"schedule\": {\n" +
                "    \"period\": {\n" +
                "      \"interval\": 5,\n" +
                "      \"unit\": \"MINUTES\"\n" +
                "    }\n" +
                "  },\n" +
                "  \"inputs\": [\n" +
                "    {\n" +
                "      \"detector_input\": {\n" +
                "        \"description\": \"windows detector for security analytics\",\n" +
                "        \"indices\": [\n" +
                "          \"windows\"\n" +
                "        ],\n" +
                "        \"custom_rules\": [],\n" +
                "        \"pre_packaged_rules\": []\n" +
                "      }\n" +
                "    }\n" +
                "  ],\n" +
                "  \"triggers\": [\n" +
                "    {\n" +
                "      \"id\": \"v70W_oMBDWZ4HMv2Cfay\",\n" +
                "      \"name\": \"windows-trigger\",\n" +
                "      \"severity\": \"1\",\n" +
                "      \"types\": [\n" +
                "        \"windows\"\n" +
                "      ],\n" +
                "      \"ids\": [\n" +
                "        \"QuarksPwDump Clearing Access History\"\n" +
                "      ],\n" +
                "      \"sev_levels\": [\n" +
                "        \"high\"\n" +
                "      ],\n" +
                "      \"tags\": [\n" +
                "        \"T0008\"\n" +
                "      ],\n" +
                "      \"actions\": []\n" +
                "    }\n" +
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
                "  \"name\": \"BCIocIalTX\",\n" +
                "  \"detector_type\": \"WINDOWS\",\n" +
                "  \"user\": {\n" +
                "    \"name\": \"JPXeGWmlMP\",\n" +
                "    \"backend_roles\": [\n" +
                "      \"lVOjTakxQl\",\n" +
                "      \"rWcHiErFQz\"\n" +
                "    ],\n" +
                "    \"roles\": [\n" +
                "      \"zEMpObrYPM\",\n" +
                "      \"all_access\"\n" +
                "    ],\n" +
                "    \"custom_attribute_names\": [\n" +
                "      \"test_attr=test\"\n" +
                "    ],\n" +
                "    \"user_requested_tenant\": null\n" +
                "  },\n" +
                "  \"enabled\": false,\n" +
                "  \"enabled_time\": null,\n" +
                "  \"inputs\": [\n" +
                "    {\n" +
                "      \"detector_input\": {\n" +
                "        \"description\": \"windows detector for security analytics\",\n" +
                "        \"indices\": [\n" +
                "          \"windows\"\n" +
                "        ],\n" +
                "        \"custom_rules\": [],\n" +
                "        \"pre_packaged_rules\": []\n" +
                "      }\n" +
                "    }\n" +
                "  ],\n" +
                "  \"triggers\": [\n" +
                "    {\n" +
                "      \"id\": \"v70W_oMBDWZ4HMv2Cfay\",\n" +
                "      \"name\": \"windows-trigger\",\n" +
                "      \"severity\": \"1\",\n" +
                "      \"types\": [\n" +
                "        \"windows\"\n" +
                "      ],\n" +
                "      \"ids\": [\n" +
                "        \"QuarksPwDump Clearing Access History\"\n" +
                "      ],\n" +
                "      \"sev_levels\": [\n" +
                "        \"high\"\n" +
                "      ],\n" +
                "      \"tags\": [\n" +
                "        \"T0008\"\n" +
                "      ],\n" +
                "      \"actions\": []\n" +
                "    }\n" +
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