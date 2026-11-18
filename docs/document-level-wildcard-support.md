# Document-level wildcard support

Security Analytics compiles rules against live source field types. Rules using
wildcard fields send native query DSL JSON in `DocLevelQuery.query` to Alerting
(the root query clause, not a `query` envelope). Alerting parses the object and
stores its native clause in the percolator query field. Non-JSON query strings
retain their legacy `query_string` path. Invalid JSON is rejected, not silently
treated as a legacy query.

Wildcard query-index mappings retain their original type and parameters. They
must not be remapped to text: keyword-tokenized text analysis collides with
literal `_ws_` values and cannot index tokens over Lucene's 32,766-byte limit.
Long wildcard values should use `doc_values: false` to avoid the separate
doc-values term-length limit.

## Alerting companion

The approved companion parses JSON DSL and rewrites field references rather than
replacing substrings in wildcard patterns or term values. It handles boolean
clauses, wildcard/regexp/term clauses, exists fields, and embedded `query_string`
leaves. Quoted query-string values are not rewritten.

Suffixes use concrete source mapping metadata. Actual multifields use their
parent's suffixed name (`message_<index>_<monitor>.wildcard`), whereas object
children suffix their own leaf name. Aliases resolve to their source target.
Native queries are rewritten for each backing index's mapping shape.
Percolator results are scoped back to each native variant's concrete source
index, including negative-only queries whose missing fields could otherwise
match another index's document.

Default fan-out fetching falls back to full `_source` for native JSON queries and
queries referencing actual multifields. Multifields have no independent source
values: reconstructing fetched values as dotted keys changes the percolator's
document shape.

## Limits and operational considerations

Mixed source mappings that assign `wildcard` and an incompatible type to the
same rule field are rejected explicitly rather than silently dropping matches.
Document-level monitors retain Alerting's existing index selection restrictions;
use an index alias, not an unsupported wildcard index-name pattern.

Native wildcard queries may not support percolator query-term extraction. Such
queries require verification against candidate documents instead of benefiting
from extracted-term pruning; this is a performance consideration, not a reason
to fall back to unsupported wildcard `query_string` matching. Monitor large
document batches and broad wildcard patterns accordingly.

Build and deploy the companion alongside Security Analytics:

```sh
cd ../alerting
./gradlew :alerting:publishPluginZipPublicationToMavenLocal -Dopensearch.version=3.10.0-SNAPSHOT
```

## Coverage

`DetectorMonitorConfigTests` verifies that wildcard mappings are not overridden.
`DetectorRestApiIT` covers direct fields, wildcard-only parameters, aliases,
multifields, literal `_ws_`, and values longer than 32,766 bytes. Each document
case executes a non-aggregation rule against matching and non-matching documents
and verifies only the matching document's finding. Bucket-level compound cases
cover AND, list/OR, NOT, and literal escaped `*`/`?` characters.

```sh
./gradlew integTest --tests 'org.opensearch.securityanalytics.resthandler.DetectorRestApiIT' -Dtests.method='testDocLevel*'
```