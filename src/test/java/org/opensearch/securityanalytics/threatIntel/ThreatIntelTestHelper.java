/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.securityanalytics.threatIntel;

import static org.apache.lucene.tests.util.LuceneTestCase.random;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.opensearch.test.OpenSearchTestCase.randomBoolean;
import static org.opensearch.test.OpenSearchTestCase.randomIntBetween;
import static org.opensearch.test.OpenSearchTestCase.randomNonNegativeLong;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.IntStream;


import org.opensearch.OpenSearchException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.replication.ReplicationResponse;
import org.opensearch.common.Randomness;
import org.opensearch.common.UUIDs;
import org.opensearch.common.collect.Tuple;
import org.opensearch.core.index.shard.ShardId;

import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.RandomObjects;

public class ThreatIntelTestHelper {

    public static final int MAX_SEQ_NO = 10000;
    public static final int MAX_PRIMARY_TERM = 10000;
    public static final int MAX_VERSION = 10000;
    public static final int MAX_SHARD_ID = 100;

    public static final int RANDOM_STRING_MIN_LENGTH = 2;
    public static final int RANDOM_STRING_MAX_LENGTH = 16;

    private static String randomString() {
        return OpenSearchTestCase.randomAlphaOfLengthBetween(RANDOM_STRING_MIN_LENGTH, RANDOM_STRING_MAX_LENGTH);
    }

    public static String randomLowerCaseString() {
        return randomString().toLowerCase(Locale.ROOT);
    }

    public static List<String> randomLowerCaseStringList() {
        List<String> stringList = new ArrayList<>();
        stringList.add(randomLowerCaseString());
        return stringList;
    }

    /**
     * Returns random {@link IndexResponse} by generating inputs using random functions.
     * It is not guaranteed to generate every possible values, and it is not required since
     * it is used by the unit test and will not be validated by the cluster.
     */
    private static IndexResponse randomIndexResponse() {
        String index = randomLowerCaseString();
        String indexUUid = UUIDs.randomBase64UUID();
        int shardId = randomIntBetween(0, MAX_SHARD_ID);
        String id = UUIDs.randomBase64UUID();
        long seqNo = randomIntBetween(0, MAX_SEQ_NO);
        long primaryTerm = randomIntBetween(0, MAX_PRIMARY_TERM);
        long version = randomIntBetween(0, MAX_VERSION);
        boolean created = randomBoolean();
        boolean forcedRefresh = randomBoolean();
        Tuple<ReplicationResponse.ShardInfo, ReplicationResponse.ShardInfo> shardInfo = RandomObjects.randomShardInfo(random());
        IndexResponse actual = new IndexResponse(new ShardId(index, indexUUid, shardId), id, seqNo, primaryTerm, version, created);
        actual.setForcedRefresh(forcedRefresh);
        actual.setShardInfo(shardInfo.v1());

        return actual;
    }

    // Generate Random Bulk Response with noOfSuccessItems as BulkItemResponse, and include BulkItemResponse.Failure with
    // random error message, if hasFailures is true.
    public static BulkResponse generateRandomBulkResponse(int noOfSuccessItems, boolean hasFailures) {
        long took = randomNonNegativeLong();
        long ingestTook = randomNonNegativeLong();
        if (noOfSuccessItems < 1) {
            return new BulkResponse(null, took, ingestTook);
        }
        List<BulkItemResponse> items = new ArrayList<>();
        IntStream.range(0, noOfSuccessItems)
                .forEach(shardId -> items.add(new BulkItemResponse(shardId, DocWriteRequest.OpType.CREATE, randomIndexResponse())));
        if (hasFailures) {
            final BulkItemResponse.Failure failedToIndex = new BulkItemResponse.Failure(
                    randomLowerCaseString(),
                    randomLowerCaseString(),
                    new OpenSearchException(randomLowerCaseString())
            );
            items.add(new BulkItemResponse(randomIntBetween(0, MAX_SHARD_ID), DocWriteRequest.OpType.CREATE, failedToIndex));
        }
        return new BulkResponse(items.toArray(BulkItemResponse[]::new), took, ingestTook);
    }

    public static StringBuilder buildFieldNameValuePair(Object field, Object value) {
        StringBuilder builder = new StringBuilder();
        builder.append("\"").append(field).append("\":");
        if (!(value instanceof String)) {
            return builder.append(value);
        }
        return builder.append("\"").append(value).append("\"");
    }

    public static String removeStartAndEndObject(String content) {
        assertNotNull(content);
        assertTrue("content length should be at least 2", content.length() > 1);
        return content.substring(1, content.length() - 1);
    }

    public static double[] toDoubleArray(float[] input) {
        return IntStream.range(0, input.length).mapToDouble(i -> input[i]).toArray();
    }

}

