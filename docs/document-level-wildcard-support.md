# Document-level wildcard support

Security Analytics compiles rules against live source field types. Rules using
wildcard fields send native query DSL JSON in `DocLevelQuery.query` to Alerting
(the root query clause, not a `query` envelope). Alerting parses the object and
stores its native clause in the percolator query field. Non-JSON query strings
retain their legacy `query_string` path. Invalid JSON is rejected, not silently
treated as a legacy query.

Field-type discovery includes data streams and merges every open backing index's
mappings. Bucket-monitor timestamp lookup also includes data streams. Regression
coverage checks native queries on detector creation and update after rollover.

Wildcard query-index mappings retain their original type and parameters. They
must not be remapped to text: keyword-tokenized text analysis collides with
literal `_ws_` values and cannot index tokens over Lucene's 32,766-byte limit.
Long wildcard values should use `doc_values: false` to avoid the separate
doc-values term-length limit.

## Sigma modifier compatibility

Audited against every modifier registered by Java `SigmaModifierFacade` (2026-11-18).
The table describes the mapping-aware public `OSQueryBackend.convertRule` path.
Wildcard fields are strings, not numeric values or IP addresses.

| Modifier | Wildcard mapping | Semantics / limitations |
|---|---|---|
| `all` | Supported | AND between list values; expansions within each value remain OR alternatives. |
| `contains` | Supported | Adds leading/trailing glob `*`; preserves spaces and escaped literal `*`/`?`. |
| `startswith`, `endswith` | Supported | Adds trailing / leading glob `*`; no analyzer tokenization. |
| `base64` | Supported | Exact encoded string; `base64\|contains` searches an encoded substring. Glob input is rejected by the modifier. |
| `base64offset` | Supported | Three existing alignment alternatives, OR-linked; `base64offset\|contains` wraps each in `*`. |
| `wide` | Supported with existing encoding constraints | Existing UTF-16LE byte-to-UTF-8-string transformation; ASCII gives interleaved NULs, which native DSL preserves. `wide\|base64` is supported. Not a general binary/non-ASCII UTF-16 codec. |
| `utf16`, `utf16le`, `utf16be` | Not registered | Rejected by the parser; `wide` is the only registered UTF-16-style modifier. `SigmaRule` currently wraps modifier parsing failures as detection-definition errors. |
| `windash` | Supported | Existing `-` / `/` flag alternatives, OR-linked and independently expanded for multiple flags. Parsed literal/glob segments preserve spaces, literal `_ws_`, and escaped literal `*`/`?`; legacy text rendering still encodes whitespace. |
| `re` | Restricted to Java/Lucene common subset | Native Lucene full-value regexp, not Java/PCRE search. Raw patterns preserve spaces, literal `_ws_`, and escaped literal glob characters, including through `re\|contains`, `re\|startswith`, and `re\|endswith`. Supports literals, `.`, ordinary grouping, alternation, quantifiers, and simple character classes. Rejects Java anchors, letter/digit escapes (including backreferences and shorthand classes), lookarounds/flags, lazy/possessive quantifiers, and unescaped Lucene-only operators. Use `re\|contains` for substring matching where appropriate. |
| `cidr` | Rejected | Requires an `ip` mapping; emits a native term query whose CIDR value the IP mapper interprets as a network. A wildcard string prefix/glob or numeric/lexical range is not equivalent. Existing Sigma CIDR validation supports IPv4 only. |
| `lt`, `lte`, `gt`, `gte` | Rejected | Require a known numeric mapping; native range query preserves operator inclusivity. Wildcard mapper range queries are unsupported; lexical ordering would not implement Sigma numeric comparison. |

Comparisons on numeric siblings and CIDR on IP siblings work in structured
wildcard rules, including negation. These native typed leaves also work without
a wildcard sibling when mapping metadata is supplied. Supported numeric types:
`byte`, `short`, `integer`, `long`, `unsigned_long`, `half_float`, `float`,
`double`, `scaled_float`. Unknown, string, boolean, date, and IP mappings are
not accepted for numeric comparisons. YAML `Integer`/`Long` and `Float`/`Double`
values retain their original precision (no narrowing to int/float); range bounds
use their decimal representation. Decimal YAML values retain the parser's IEEE
754 double precision, not arbitrary decimal precision. Integers outside signed
64-bit range (including the upper half of `unsigned_long`) and arbitrary-precision
numeric inputs are unsupported by the Sigma value parser; do not use them as
numeric rule bounds. Mapper-specific coercion remains the mapper's responsibility.
Numeric/boolean equality on wildcard fields remains literal string equality,
not arithmetic or boolean interpretation.

When typed-only structured compilation includes a fieldless keyword and no
text/keyword/wildcard mappings are known, that leaf retains the legacy unbound
`query_string` search, including negation. It must not become an empty boolean
query that matches all documents. Native regex wrappers group top-level
alternations before adding `.*`, and distinguish an escaped literal `\$` from
an end anchor. Legacy query-string regex wrapping/whitespace rendering remains
unchanged. Quantified escaped punctuation such as `\*+`, `\?+`, and `\++` is
supported; lazy/possessive quantifiers are still rejected.

Modifier order and input type checks are retained: e.g. `contains|base64` and
`contains|re` are rejected, as are numeric inputs to string modifiers. Without
mapping metadata the legacy backend behavior remains unchanged; it cannot prove
mapper compatibility. Regex retains both its raw pattern and legacy encoded
representation; windash transforms parsed literal/glob segments without string
roundtrips. Other existing modifier encoding and regex-parser limitations are
not broadened by wildcard DSL support.

Regression tests exercise YAML parsing through `convertRule` and compare native
query builders (including expansion structure), rather than private renderers.
They do not replace live mapper/percolator integration testing.

```sh
./gradlew test --tests 'org.opensearch.securityanalytics.rules.backend.QueryBackendTests' --offline
./gradlew test --tests 'org.opensearch.securityanalytics.rules.*' --offline
```

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

Mixed source mappings that assign `wildcard` and any other type, numeric and
non-numeric types (e.g. `long`/`keyword`), or `ip` and any other type (e.g.
`ip`/`text`) to the same field are rejected explicitly. Conflict selection and
type diagnostics are sorted, independent of concrete-index iteration order.
Different numeric mapping types remain compatible for range compilation, with
coercion applied by each concrete mapper. Missing fields do not conflict, and
legacy non-typed conflicts such as `text`/`keyword` retain the first mapping type.
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