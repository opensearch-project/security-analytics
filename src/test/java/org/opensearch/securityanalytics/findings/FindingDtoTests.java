/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.findings;

import java.time.Instant;
import java.util.List;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.FindingDocument;
import org.opensearch.securityanalytics.action.FindingDto;
import org.opensearch.test.OpenSearchTestCase;

public class FindingDtoTests extends OpenSearchTestCase {


    public void testFindingDTO_creation() {

        FindingDocument findingDocument1 = new FindingDocument("test_index1", "doc1", true, "document 1 payload");
        FindingDocument findingDocument2 = new FindingDocument("test_index1", "doc2", true, "document 2 payload");
        FindingDocument findingDocument3 = new FindingDocument("test_index1", "doc3", true, "document 3 payload");

        Instant now = Instant.now();

        FindingDto findingDto = new FindingDto(
                "detectorId",
                "findingId",
                List.of("doc1", "doc2", "doc3"),
                "my_index",
                List.of(new DocLevelQuery("1","myQuery","fieldA:valABC", List.of())),
                now,
                List.of(findingDocument1, findingDocument2, findingDocument3)
        );

        assertEquals("detectorId", findingDto.getDetectorId());
        assertEquals("findingId", findingDto.getId());
        assertEquals(List.of("doc1", "doc2", "doc3"), findingDto.getRelatedDocIds());
        assertEquals("my_index", findingDto.getIndex());
        assertEquals(List.of(new DocLevelQuery("1","myQuery","fieldA:valABC", List.of())), findingDto.getDocLevelQueries());
        assertEquals(now, findingDto.getTimestamp());
        assertEquals(List.of(findingDocument1, findingDocument2, findingDocument3), findingDto.getDocuments());
    }

}
