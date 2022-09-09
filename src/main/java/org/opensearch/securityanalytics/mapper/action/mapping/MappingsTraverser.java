package org.opensearch.securityanalytics.mapper.action.mapping;

import org.opensearch.cluster.metadata.MappingMetadata;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Stack;

import static org.opensearch.securityanalytics.mapper.action.mapping.MapperUtils.NESTED;
import static org.opensearch.securityanalytics.mapper.action.mapping.MapperUtils.PROPERTIES;
import static org.opensearch.securityanalytics.mapper.action.mapping.MapperUtils.TYPE;
import static org.opensearch.securityanalytics.mapper.action.mapping.MapperUtils.ALIAS;

public class MappingsTraverser {

    private final MappingMetadata mappingMetadata;

    Stack<Node> nodeStack = new Stack<>();

    public MappingsTraverser(MappingMetadata mappingMetadata) {
        this.mappingMetadata = mappingMetadata;

    }

    /**
    * Traverses index mappings and returns flat field names
    * */
    public List<String> extractFlatNonAliasFields() {

        Map<String, Object> map = mappingMetadata.getSourceAsMap();

        List<String> flatProperties = new ArrayList<>();
        Map<String, Object> rootProperties = (Map<String, Object>) map.get(PROPERTIES);
        rootProperties.forEach((k, v) -> {
            nodeStack.push(new Node(Map.of(k, v), ""));
        });

        while (nodeStack.size() > 0) {
            Node node = nodeStack.pop();
            // visit node
            if (isLeaf(node.node)) {
                Map.Entry<String, Object> elem = node.node.entrySet().iterator().next();
                Map<String, Object> properties = (Map<String, Object>) elem.getValue();
                if (properties.get(TYPE).equals(ALIAS) == false) {
                    String fullPath = node.currentPath;
                    fullPath += (
                            fullPath.length() > 0 ?
                                    "."  + elem.getKey():
                                    "" + elem.getKey()
                    );
                    flatProperties.add(fullPath);
                }
            } else {
                Map<String, Object> children = getChildren(node.node);
                String currentNodeName = getNodeName(node.node);
                children.forEach((k, v) -> {
                    String currentPath =
                            node.currentPath.length() > 0 ?
                                    node.currentPath + "." + currentNodeName :
                                    currentNodeName;
                    nodeStack.push(new Node(Map.of(k, v), currentPath));
                });
            }
        }
        return flatProperties;
    }

    private String getNodeName(Map<String, Object> node) {
        return node.entrySet().iterator().next().getKey();
    }

    private Map<String, Object> getChildren(Map<String, Object> node) {
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

    private boolean isLeaf(Map<String, Object> node) {
        Map.Entry<String, Object> entry = node.entrySet().iterator().next();
        Map<String, Object> properties = (Map<String, Object>) entry.getValue();
        return properties.containsKey(PROPERTIES) == false &&
               properties.containsKey(NESTED) == false;
    }

    static class Node {
        Map<String, Object> node;
        String currentPath;

        public Node(Map<String, Object> node, String currentPath) {
            this.node = node;
            this.currentPath = currentPath;
        }
    }
}
