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

/**
 A job that runs periodically in the cluster.
 *
 All implementations of [ScheduledJob]s are stored in the [SCHEDULED_JOBS_INDEX] index and are scheduled in a
 single global Scheduler running on each node. Each implementation should have its own separate APIs for writing,
 updating and deleting instances of that job type into the [SCHEDULED_JOBS_INDEX] index. The index is periodically
 scanned for updates which are then scheduled or unscheduled with the Scheduler.
 *
 Like all documents in OpenSearch [ScheduledJob]s also have an [id] and a [version].  Jobs that have not been
 persisted in the cluster should use the special sentinel values [NO_ID] and [NO_VERSION] for these fields.
 */
public abstract class ScheduledJob implements Writeable,ToXContentObject {

    /** The name of the ElasticSearch index in which we store jobs */
    final static String SCHEDULED_JOBS_INDEX = ".opendistro-alerting-config";
    final static String DOC_LEVEL_QUERIES_INDEX = ".opensearch-alerting-queries";

    final static String NO_ID = "";

    final static String NO_VERSION = "1L";

    public final static MapParams XCONTENT_WITH_TYPE = new ToXContent.MapParams(Map.of("with_type", "true"));

//    public XContentBuilder toXContentWithType(XContentBuilder builder) {
//        return this.toXContent(builder, XCONTENT_WITH_TYPE);
//    }

/**
 This function parses the job, delegating to the specific subtype parser registered in the [XContentParser.getXContentRegistry]
 at runtime.  Each concrete job subclass is expected to register a parser in this registry.
 The Job's json representation is expected to be of the form:
 { "<job_type>" : { <job fields> } }
 *
 If the job comes from an OpenSearch index it's [id] and [version] can also be supplied.
 */
//    @Throws(IOException::class)
//    fun parse(xcp: XContentParser, id: String = NO_ID, version: Long = NO_VERSION): ScheduledJob {
//        ensureExpectedToken(Token.START_OBJECT, xcp.nextToken(), xcp)
//        ensureExpectedToken(Token.FIELD_NAME, xcp.nextToken(), xcp)
//        ensureExpectedToken(Token.START_OBJECT, xcp.nextToken(), xcp)
//        val job = xcp.namedObject(ScheduledJob::class.java, xcp.currentName(), null)
//        ensureExpectedToken(Token.END_OBJECT, xcp.nextToken(), xcp)
//        return job.fromDocument(id, version)
//    }
//
//    /**
//     * This function parses the job, but expects the type to be passed in. This is for the specific
//     * use case in sweeper where we first want to check if the job is allowed to be swept before
//     * trying to fully parse it. If you need to parse a job, you most likely want to use
//     * the above parse function.
//     */
//    @Throws(IOException::class)
//    fun parse(xcp: XContentParser, type: String, id: String = NO_ID, version: Long = NO_VERSION): ScheduledJob {
//        ensureExpectedToken(Token.START_OBJECT, xcp.nextToken(), xcp)
//        val job = xcp.namedObject(ScheduledJob::class.java, type, null)
//        ensureExpectedToken(Token.END_OBJECT, xcp.nextToken(), xcp)
//        return job.fromDocument(id, version)
//    }
//
//    /** The id of the job in the [SCHEDULED_JOBS_INDEX] or [NO_ID] if not persisted */
//    val id: String
//
//    /** The version of the job in the [SCHEDULED_JOBS_INDEX] or [NO_VERSION] if not persisted  */
//    val version: Long
//
//    /** The name of the job */
//    val name: String
//
//    /** The type of the job */
//    val type: String
//
//    /** Controls whether the job will be scheduled or not  */
//    val enabled: Boolean
//
//    /** The schedule for running the job  */
//    val schedule: Schedule
//
//    /** The last time the job was updated */
//    val lastUpdateTime: Instant
//
//    /** The time the job was enabled */
//    val enabledTime: Instant?
//
//    /** Copy constructor for persisted jobs */
//    fun fromDocument(id: String, version: Long): ScheduledJob
}