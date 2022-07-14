/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionIdentifier;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.condition.ConditionLexer;
import org.opensearch.securityanalytics.rules.condition.ConditionParser;
import org.opensearch.securityanalytics.rules.condition.ConditionSelector;
import org.opensearch.securityanalytics.rules.condition.ConditionTraverseVisitor;
import org.opensearch.securityanalytics.rules.condition.ConditionValueExpression;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;


import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class SigmaCondition {

    private final String identifier = "[a-zA-Z0-9-_]+";

    private final List<String> quantifier = List.of("1", "any", "all");

    private final String identifierPattern = "[a-zA-Z0-9*_]+";

    private final List<Either<List<String>, String>> selector = List.of(Either.left(quantifier), Either.right("of"), Either.right(identifierPattern));

    private final List<String> operators = List.of("not ", " and ", " or ");

    private String condition;

    private SigmaDetections detections;

    private ConditionParser parser;

    private ConditionTraverseVisitor conditionVisitor;

    public SigmaCondition(String condition, SigmaDetections detections) {
        this.condition = condition;
        this.detections = detections;

        ConditionLexer lexer = new ConditionLexer(CharStreams.fromString(condition));
        this.parser = new ConditionParser(new CommonTokenStream(lexer));
        this.conditionVisitor = new ConditionTraverseVisitor(this);
    }

    public ConditionItem parsed() throws SigmaConditionError {
        Either<ConditionItem, String> itemOrCondition = conditionVisitor.visit(parser.start());
        if (itemOrCondition.isLeft()) {
            return itemOrCondition.getLeft();
        } else {
            return Objects.requireNonNull(parsed(condition)).isLeft()? Objects.requireNonNull(parsed(condition)).getLeft():
                    ((Objects.requireNonNull(parsed(condition))).isMiddle()? Objects.requireNonNull(parsed(condition)).getMiddle():
                            Objects.requireNonNull(parsed(condition)).get());
        }
    }

    public List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> convertArgs(
            List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> parsedArgs) throws SigmaConditionError {
        List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> newArgs = new ArrayList<>();

        for (Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> parsedArg: parsedArgs) {
            if (parsedArg.isRight()) {
                AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression> newItem = parsed(parsedArg.get());
                newArgs.add(Either.left(newItem));
            } else {
                newArgs.add(parsedArg);
            }
        }
        return newArgs;
    }

    private AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression> parsed(String token) throws SigmaConditionError {
        List<String> subTokens = List.of(token.split(" "));
        if (subTokens.size() < 3 && token.matches(identifier)) {
            ConditionIdentifier conditionIdentifier =
                    new ConditionIdentifier(Collections.singletonList(Either.right(token)));
            ConditionItem item = conditionIdentifier.postProcess(detections, null);
            return item instanceof ConditionFieldEqualsValueExpression? AnyOneOf.middleVal((ConditionFieldEqualsValueExpression) item):
                    (item instanceof ConditionValueExpression ? AnyOneOf.rightVal((ConditionValueExpression) item): AnyOneOf.leftVal(item));
        } else if (subTokens.size() == 3 && quantifier.contains(subTokens.get(0)) && selector.get(1).get().equals(subTokens.get(1)) &&
                subTokens.get(2).matches(identifierPattern)) {
            ConditionSelector conditionSelector =
                    new ConditionSelector(subTokens.get(0), subTokens.get(2));
            ConditionItem item = conditionSelector.postProcess(detections, null);
            return item instanceof ConditionFieldEqualsValueExpression? AnyOneOf.middleVal((ConditionFieldEqualsValueExpression) item):
                    (item instanceof ConditionValueExpression ? AnyOneOf.rightVal((ConditionValueExpression) item): AnyOneOf.leftVal(item));
        }
        return null;
    }
}