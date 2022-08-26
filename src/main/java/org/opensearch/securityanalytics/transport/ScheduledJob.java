/*
Copyright OpenSearch Contributors
SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.securityanalytics.transport;

//import org.opensearch.alerting.core.model.ScheduledJob.Companion.NO_ID;
//import org.opensearch.alerting.core.model.ScheduledJob.Companion.NO_VERSION;
//import org.opensearch.alerting.core.model.ScheduledJob.Companion.SCHEDULED_JOBS_INDEX;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParser.Token;
//import org.opensearch.common.xcontent.XContentParserUtils.ensureExpectedToken;
import java.io.IOException;
import java.time.Instant;


import java.util.Collections;
import java.util.Map;

public abstract class ScheduledJob implements Writeable,ToXContentObject {

    /** The name of the Opensearch index in which we store jobs */
    final static String SCHEDULED_JOBS_INDEX = ".opendistro-alerting-config";
    final static String DOC_LEVEL_QUERIES_INDEX = ".opensearch-alerting-queries";

    final static String NO_ID = "";

    final static String NO_VERSION = "1L";

    public final static MapParams XCONTENT_WITH_TYPE = new ToXContent.MapParams(Map.of("with_type", "true"));

//    public XContentBuilder toXContentWithType(XContentBuilder builder) {
//        return this.toXContent(builder, XCONTENT_WITH_TYPE);
//    }
}
