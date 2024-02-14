/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
grammar Aggregation;

GT : '>' ;
GE : '>=' ;
LT : '<' ;
LE : '<=' ;
EQ : '==' ;

COUNT : 'count' ;
SUM : 'sum' ;
MIN : 'min' ;
MAX : 'max' ;
AVG : 'avg' ;
BY : 'by' ;
LPAREN : '(' ;
RPAREN : ')' ;

DECIMAL : '-'?[0-9]+('.'[0-9]+)? ;

IDENTIFIER : [a-zA-Z*_.][a-zA-Z_0-9.]* ;
WS : [ \r\t\u000C\n]+ -> skip ;

comparison_expr : comparison_operand comp_operator comparison_operand   # ComparisonExpressionWithOperator
                ;

comparison_operand : agg_expr
                   ;

comp_operator : GT
              | GE
              | LT
              | LE
              | EQ
              ;

agg_operator : COUNT
             | SUM
             | MIN
             | MAX
             | AVG
             ;

groupby_expr : IDENTIFIER ;

agg_expr
 : agg_operator LPAREN agg_expr RPAREN BY? groupby_expr?       # AggExpressionParens
 | numeric_entity                                              # AggExpressionNumericEntity
 ;

numeric_entity : DECIMAL              # NumericConst
               | IDENTIFIER           # NumericVariable
               ;