/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;

public class RuleCategory implements Writeable, ToXContentObject {

    public static final String KEY = "key";
    public static final String DISPLAY_NAME = "display_name";
    public static final String ENABLED = "enabled";

    private String name;
    private String displayName;
    private Boolean enabled;

    public RuleCategory(StreamInput sin) throws IOException {
        this(sin.readString(), sin.readString(), sin.readBoolean());
    }

    public RuleCategory(String name, String displayName, Boolean enabled) {
        this.name = name;
        this.displayName = displayName;
        this.enabled = enabled;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(name);
        out.writeString(displayName);
        out.writeBoolean(enabled);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.startObject()
                .field(KEY, name)
                .field(DISPLAY_NAME, displayName)
                .field(ENABLED, enabled)
                .endObject();
    }

    public static final List<RuleCategory> ALL_RULE_CATEGORIES;

    static {
        List<RuleCategory> ruleCategories = new ArrayList<>();
        ruleCategories.add(new RuleCategory(Detector.DetectorType.AD_LDAP.getDetectorType(), "AD/LDAP", true));
        ruleCategories.add(new RuleCategory(Detector.DetectorType.DNS.getDetectorType(), "DNS logs", true));
        ruleCategories.add(new RuleCategory(Detector.DetectorType.NETWORK.getDetectorType(), "Netflow", true));
        ruleCategories.add(new RuleCategory(Detector.DetectorType.APACHE_ACCESS.getDetectorType(), "Apache access logs", true));
        ruleCategories.add(new RuleCategory(Detector.DetectorType.CLOUDTRAIL.getDetectorType(), "Cloud Trail logs", true));
        ruleCategories.add(new RuleCategory(Detector.DetectorType.S3.getDetectorType(), "S3 access logs", true));
        ruleCategories.add(new RuleCategory(Detector.DetectorType.WINDOWS.getDetectorType(), "Windows logs", true));
        ruleCategories.add(new RuleCategory(Detector.DetectorType.LINUX.getDetectorType(), "System logs", true));

        ALL_RULE_CATEGORIES = Collections.unmodifiableList(ruleCategories);
    }

}

