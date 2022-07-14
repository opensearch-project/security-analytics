/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
grammar Condition;

AND: 'and' ;
OR: 'or' ;
NOT: 'not';

LPAREN     : '(' ;
RPAREN     : ')' ;

SELECTOR: ('1'|'any'|'all')( ' of ' )[A-Za-z_0-9*]+ ;
IDENTIFIER: [a-zA-Z_] [a-zA-Z_0-9]* ;
WHITESPACE: [ \r\n\t]+ -> skip;

start : expression;

expression
   : (SELECTOR|IDENTIFIER)                              # identOrSelectExpression
   | LPAREN inner=expression RPAREN                     # parenExpression
   | NOT expression                                     # notExpression
   | left=expression operator=AND right=expression      # andExpression
   | left=expression operator=OR right=expression       # orExpression
   ;
