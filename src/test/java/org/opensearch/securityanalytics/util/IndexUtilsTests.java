/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.util;

import org.junit.Assert;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

import static org.opensearch.securityanalytics.TestHelpers.parser;

public class IndexUtilsTests extends OpenSearchTestCase {

    public void testGetSchemaVersion() throws IOException {
        String message = "{\"user\":{ \"name\":\"test\"},\"_meta\":{\"schema_version\": 1}}";

        int schemaVersion = IndexUtils.getSchemaVersion(message);
        Assert.assertEquals(1, schemaVersion);
    }

    public void testGetSchemaVersionWithoutMeta() throws IOException {
        String message = "{\"user\":{ \"name\":\"test\"}}";

        int schemaVersion = IndexUtils.getSchemaVersion(message);
        Assert.assertEquals(0, schemaVersion);
    }

    public void testGetSchemaVersionWithoutSchemaVersion() throws IOException {
        String message = "{\"user\":{ \"name\":\"test\"},\"_meta\":{\"test\": 1}}";

        int schemaVersion = IndexUtils.getSchemaVersion(message);
        Assert.assertEquals(0, schemaVersion);
    }

    public void testGetSchemaVersionWithNegativeSchemaVersion() {
        String message = "{\"user\":{ \"name\":\"test\"},\"_meta\":{\"schema_version\": -1}}";

        assertThrows(IllegalArgumentException.class, () -> {
            IndexUtils.getSchemaVersion(message);
        });
    }

    public void testGetSchemaVersionWithWrongSchemaVersion() {
        String message = "{\"user\":{ \"name\":\"test\"},\"_meta\":{\"schema_version\": \"wrong\"}}";

        assertThrows(IllegalArgumentException.class, () -> {
            IndexUtils.getSchemaVersion(message);
        });
    }

    public void testShouldUpdateIndexWithoutOriginalVersion() throws IOException {
        String indexContent = "{\"testIndex\":{\"settings\":{\"index\":{\"creation_date\":\"1558407515699\"," +
                "\"number_of_shards\":\"1\",\"number_of_replicas\":\"1\",\"uuid\":\"t-VBBW6aR6KpJ3XP5iISOA\"," +
                "\"version\":{\"created\":\"6040399\"},\"provided_name\":\"data_test\"}},\"mapping_version\":123," +
                "\"settings_version\":123,\"mappings\":{\"_doc\":{\"properties\":{\"name\":{\"type\":\"keyword\"}}}}}}";

        String newMapping = "{\"_meta\":{\"schema_version\":10},\"properties\":{\"name\":{\"type\":\"keyword\"}}}";
        IndexMetadata index = IndexMetadata.fromXContent(parser(indexContent));
        boolean shouldUpdateIndex = IndexUtils.shouldUpdateIndex(index, newMapping);

        Assert.assertTrue(shouldUpdateIndex);
    }

    public void testShouldUpdateIndexWithLaggedVersion() throws IOException {
        String indexContent = "{\"testIndex\":{\"settings\":{\"index\":{\"creation_date\":\"1558407515699\"," +
                "\"number_of_shards\":\"1\",\"number_of_replicas\":\"1\",\"uuid\":\"t-VBBW6aR6KpJ3XP5iISOA\"," +
                "\"version\":{\"created\":\"6040399\"},\"provided_name\":\"data_test\"}},\"mapping_version\":123," +
                "\"settings_version\":123,\"mappings\":{\"_doc\":{\"_meta\":{\"schema_version\":1},\"properties\":" +
                "{\"name\":{\"type\":\"keyword\"}}}}}}";

        String newMapping = "{\"_meta\":{\"schema_version\":10},\"properties\":{\"name\":{\"type\":\"keyword\"}}}";
        IndexMetadata index = IndexMetadata.fromXContent(parser(indexContent));
        boolean shouldUpdateIndex = IndexUtils.shouldUpdateIndex(index, newMapping);

        Assert.assertTrue(shouldUpdateIndex);
    }

    public void testShouldUpdateIndexWithSameVersion() throws IOException {
        String indexContent = "{\"testIndex\":{\"settings\":{\"index\":{\"creation_date\":\"1558407515699\"," +
                "\"number_of_shards\":\"1\",\"number_of_replicas\":\"1\",\"uuid\":\"t-VBBW6aR6KpJ3XP5iISOA\"," +
                "\"version\":{\"created\":\"6040399\"},\"provided_name\":\"data_test\"}},\"mapping_version\":\"1\"," +
                "\"settings_version\":\"1\",\"aliases_version\":\"1\",\"mappings\":" +
                "{\"_doc\":{\"_meta\":{\"schema_version\":1},\"properties\":{\"name\":{\"type\":\"keyword\"}}}}}}";

        String newMapping = "{\"_meta\":{\"schema_version\":10},\"properties\":{\"name\":{\"type\":\"keyword\"}}}";
        IndexMetadata index = IndexMetadata.fromXContent(parser(indexContent));
        boolean shouldUpdateIndex = IndexUtils.shouldUpdateIndex(index, newMapping);

        Assert.assertTrue(shouldUpdateIndex);
    }
}