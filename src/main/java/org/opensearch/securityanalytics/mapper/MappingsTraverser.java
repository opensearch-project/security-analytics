package org.opensearch.securityanalytics.mapper;

import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.common.xcontent.DeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.json.JsonXContent;

import java.io.IOException;
import java.util.*;

import static org.opensearch.securityanalytics.mapper.MapperUtils.NESTED;
import static org.opensearch.securityanalytics.mapper.MapperUtils.PROPERTIES;
import static org.opensearch.securityanalytics.mapper.MapperUtils.TYPE;
import static org.opensearch.securityanalytics.mapper.MapperUtils.ALIAS;

public class MappingsTraverser {

    private Map<String, Object> mappingsMap;

    private Set<String> typesToSkip = new HashSet<>();

    Stack<Node> nodeStack = new Stack<>();

    private List<MappingsTraverserListener> mappingsTraverserListeners = new ArrayList<>();

    public MappingsTraverser(MappingMetadata mappingMetadata) {
        this.mappingsMap = mappingMetadata.getSourceAsMap();
    }
    public MappingsTraverser(Map<String, Object> mappingsMap, Set<String> typesToSkip) {
        this.mappingsMap = mappingsMap;
        this.typesToSkip = typesToSkip;
    }
    public MappingsTraverser(String mappings, Set<String> typesToSkip) throws IOException {

        this.typesToSkip = typesToSkip;

        try (
                XContentParser parser = JsonXContent.jsonXContent
                        .createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                mappings)
        ) {
            this.mappingsMap = parser.map();
        }
    }


    public List<String> extractFlatNonAliasFields() {
        List<String> flatProperties = new ArrayList<>();

        this.typesToSkip.add(ALIAS);
        this.mappingsTraverserListeners.add((node, properties, fullPath) -> flatProperties.add(fullPath));
        traverse();

        return flatProperties;
    }

    /**
    * Traverses index mappings and returns flat field names
    * */
    public void traverse() {
        Map<String, Object> rootProperties = (Map<String, Object>) this.mappingsMap.get(PROPERTIES);
        rootProperties.forEach((k, v) -> {
            nodeStack.push(new Node(Map.of(k, v), ""));
        });

        while (nodeStack.size() > 0) {
            Node node = nodeStack.pop();
            // visit node
            if (node.isLeaf()) {
                Map.Entry<String, Object> elem = node.node.entrySet().iterator().next();
                Map<String, Object> properties = (Map<String, Object>) elem.getValue();
                // check if we should skip this property type
                if (typesToSkip.contains(properties.get(TYPE))) {
                    continue;
                }
                String fullPath = node.currentPath;
                fullPath += (
                        fullPath.length() > 0 ?
                                "." + elem.getKey() :
                                "" + elem.getKey()
                );
                notifyLeafVisited(node, properties, fullPath);
            } else {
                Map<String, Object> children = node.getChildren();
                String currentNodeName = node.getNodeName();
                children.forEach((k, v) -> {
                    String currentPath =
                            node.currentPath.length() > 0 ?
                                    node.currentPath + "." + currentNodeName :
                                    currentNodeName;
                    nodeStack.push(new Node(Map.of(k, v), currentPath));
                });
            }
        }
    }

    private void notifyLeafVisited(Node node, Map<String, Object> properties, String fullPath) {
        this.mappingsTraverserListeners.forEach(
                e -> e.onLeafVisited(node, properties, fullPath)
        );
    }

    private String getNodeName(Map<String, Object> node) {
        return node.entrySet().iterator().next().getKey();
    }

    static class Node {
        Map<String, Object> node;
        String currentPath;
        String name;

        public Node(Map<String, Object> node, String currentPath) {
            this.node = node;
            this.currentPath = currentPath;
        }

        public String getNodeName() {
            if (name == null) {
                name = node.entrySet().iterator().next().getKey();
            }
            return name;
        }

        public Map<String, Object> getChildren() {
            Map.Entry<String, Object> entry = node.entrySet().iterator().next();
            Map<String, Object> properties = (Map<String, Object>) entry.getValue();
            if (properties.containsKey(PROPERTIES)) {
                return (Map<String, Object>) properties.get(PROPERTIES);
            } else if (properties.containsKey(NESTED)) {
                return (Map<String, Object>) properties.get(NESTED);
            } else {
                return null;
            }
        }

        public boolean isLeaf() {
            Map.Entry<String, Object> entry = node.entrySet().iterator().next();
            Map<String, Object> properties = (Map<String, Object>) entry.getValue();
            return properties.containsKey(PROPERTIES) == false &&
                    properties.containsKey(NESTED) == false;
        }
    }

    public void addListener(MappingsTraverserListener l) {
        this.mappingsTraverserListeners.add(l);
    }

    public interface MappingsTraverserListener {
        void onLeafVisited(Node node, Map<String, Object> properties, String fullPath);
    }

}
