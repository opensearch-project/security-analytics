// Generated from java-escape by ANTLR 4.11.1
package org.opensearch.securityanalytics.rules.condition.aggregation;
import org.antlr.v4.runtime.Lexer;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.TokenStream;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.atn.*;
import org.antlr.v4.runtime.dfa.DFA;
import org.antlr.v4.runtime.misc.*;

@SuppressWarnings({"all", "warnings", "unchecked", "unused", "cast", "CheckReturnValue"})
public class AggregationLexer extends Lexer {
    static { RuntimeMetaData.checkVersion("4.11.1", RuntimeMetaData.VERSION); }

    protected static final DFA[] _decisionToDFA;
    protected static final PredictionContextCache _sharedContextCache =
        new PredictionContextCache();
    public static final int
        GT=1, GE=2, LT=3, LE=4, EQ=5, COUNT=6, SUM=7, MIN=8, MAX=9, AVG=10, BY=11,
        LPAREN=12, RPAREN=13, DECIMAL=14, IDENTIFIER=15, WS=16;
    public static String[] channelNames = {
        "DEFAULT_TOKEN_CHANNEL", "HIDDEN"
    };

    public static String[] modeNames = {
        "DEFAULT_MODE"
    };

    private static String[] makeRuleNames() {
        return new String[] {
            "GT", "GE", "LT", "LE", "EQ", "COUNT", "SUM", "MIN", "MAX", "AVG", "BY",
            "LPAREN", "RPAREN", "DECIMAL", "IDENTIFIER", "WS"
        };
    }
    public static final String[] ruleNames = makeRuleNames();

    private static String[] makeLiteralNames() {
        return new String[] {
            null, "'>'", "'>='", "'<'", "'<='", "'=='", "'count'", "'sum'", "'min'",
            "'max'", "'avg'", "'by'", "'('", "')'"
        };
    }
    private static final String[] _LITERAL_NAMES = makeLiteralNames();
    private static String[] makeSymbolicNames() {
        return new String[] {
            null, "GT", "GE", "LT", "LE", "EQ", "COUNT", "SUM", "MIN", "MAX", "AVG",
            "BY", "LPAREN", "RPAREN", "DECIMAL", "IDENTIFIER", "WS"
        };
    }
    private static final String[] _SYMBOLIC_NAMES = makeSymbolicNames();
    public static final Vocabulary VOCABULARY = new VocabularyImpl(_LITERAL_NAMES, _SYMBOLIC_NAMES);

    /**
     * @deprecated Use {@link #VOCABULARY} instead.
     */
    @Deprecated
    public static final String[] tokenNames;
    static {
        tokenNames = new String[_SYMBOLIC_NAMES.length];
        for (int i = 0; i < tokenNames.length; i++) {
            tokenNames[i] = VOCABULARY.getLiteralName(i);
            if (tokenNames[i] == null) {
                tokenNames[i] = VOCABULARY.getSymbolicName(i);
            }

            if (tokenNames[i] == null) {
                tokenNames[i] = "<INVALID>";
            }
        }
    }

    @Override
    @Deprecated
    public String[] getTokenNames() {
        return tokenNames;
    }

    @Override

    public Vocabulary getVocabulary() {
        return VOCABULARY;
    }


    public AggregationLexer(CharStream input) {
        super(input);
        _interp = new LexerATNSimulator(this,_ATN,_decisionToDFA,_sharedContextCache);
    }

    @Override
    public String getGrammarFileName() { return "Aggregation.g4"; }

    @Override
    public String[] getRuleNames() { return ruleNames; }

    @Override
    public String getSerializedATN() { return _serializedATN; }

    @Override
    public String[] getChannelNames() { return channelNames; }

    @Override
    public String[] getModeNames() { return modeNames; }

    @Override
    public ATN getATN() { return _ATN; }

    public static final String _serializedATN =
        "\u0004\u0000\u0010i\u0006\uffff\uffff\u0002\u0000\u0007\u0000\u0002\u0001"+
        "\u0007\u0001\u0002\u0002\u0007\u0002\u0002\u0003\u0007\u0003\u0002\u0004"+
        "\u0007\u0004\u0002\u0005\u0007\u0005\u0002\u0006\u0007\u0006\u0002\u0007"+
        "\u0007\u0007\u0002\b\u0007\b\u0002\t\u0007\t\u0002\n\u0007\n\u0002\u000b"+
        "\u0007\u000b\u0002\f\u0007\f\u0002\r\u0007\r\u0002\u000e\u0007\u000e\u0002"+
        "\u000f\u0007\u000f\u0001\u0000\u0001\u0000\u0001\u0001\u0001\u0001\u0001"+
        "\u0001\u0001\u0002\u0001\u0002\u0001\u0003\u0001\u0003\u0001\u0003\u0001"+
        "\u0004\u0001\u0004\u0001\u0004\u0001\u0005\u0001\u0005\u0001\u0005\u0001"+
        "\u0005\u0001\u0005\u0001\u0005\u0001\u0006\u0001\u0006\u0001\u0006\u0001"+
        "\u0006\u0001\u0007\u0001\u0007\u0001\u0007\u0001\u0007\u0001\b\u0001\b"+
        "\u0001\b\u0001\b\u0001\t\u0001\t\u0001\t\u0001\t\u0001\n\u0001\n\u0001"+
        "\n\u0001\u000b\u0001\u000b\u0001\f\u0001\f\u0001\r\u0003\rM\b\r\u0001"+
        "\r\u0004\rP\b\r\u000b\r\f\rQ\u0001\r\u0001\r\u0004\rV\b\r\u000b\r\f\r"+
        "W\u0003\rZ\b\r\u0001\u000e\u0001\u000e\u0005\u000e^\b\u000e\n\u000e\f"+
        "\u000ea\t\u000e\u0001\u000f\u0004\u000fd\b\u000f\u000b\u000f\f\u000fe"+
        "\u0001\u000f\u0001\u000f\u0000\u0000\u0010\u0001\u0001\u0003\u0002\u0005"+
        "\u0003\u0007\u0004\t\u0005\u000b\u0006\r\u0007\u000f\b\u0011\t\u0013\n"+
        "\u0015\u000b\u0017\f\u0019\r\u001b\u000e\u001d\u000f\u001f\u0010\u0001"+
        "\u0000\u0004\u0001\u000009\u0005\u0000**..AZ__az\u0005\u0000..09AZ__a"+
        "z\u0003\u0000\t\n\f\r  n\u0000\u0001\u0001\u0000\u0000\u0000\u0000\u0003"+
        "\u0001\u0000\u0000\u0000\u0000\u0005\u0001\u0000\u0000\u0000\u0000\u0007"+
        "\u0001\u0000\u0000\u0000\u0000\t\u0001\u0000\u0000\u0000\u0000\u000b\u0001"+
        "\u0000\u0000\u0000\u0000\r\u0001\u0000\u0000\u0000\u0000\u000f\u0001\u0000"+
        "\u0000\u0000\u0000\u0011\u0001\u0000\u0000\u0000\u0000\u0013\u0001\u0000"+
        "\u0000\u0000\u0000\u0015\u0001\u0000\u0000\u0000\u0000\u0017\u0001\u0000"+
        "\u0000\u0000\u0000\u0019\u0001\u0000\u0000\u0000\u0000\u001b\u0001\u0000"+
        "\u0000\u0000\u0000\u001d\u0001\u0000\u0000\u0000\u0000\u001f\u0001\u0000"+
        "\u0000\u0000\u0001!\u0001\u0000\u0000\u0000\u0003#\u0001\u0000\u0000\u0000"+
        "\u0005&\u0001\u0000\u0000\u0000\u0007(\u0001\u0000\u0000\u0000\t+\u0001"+
        "\u0000\u0000\u0000\u000b.\u0001\u0000\u0000\u0000\r4\u0001\u0000\u0000"+
        "\u0000\u000f8\u0001\u0000\u0000\u0000\u0011<\u0001\u0000\u0000\u0000\u0013"+
        "@\u0001\u0000\u0000\u0000\u0015D\u0001\u0000\u0000\u0000\u0017G\u0001"+
        "\u0000\u0000\u0000\u0019I\u0001\u0000\u0000\u0000\u001bL\u0001\u0000\u0000"+
        "\u0000\u001d[\u0001\u0000\u0000\u0000\u001fc\u0001\u0000\u0000\u0000!"+
        "\"\u0005>\u0000\u0000\"\u0002\u0001\u0000\u0000\u0000#$\u0005>\u0000\u0000"+
        "$%\u0005=\u0000\u0000%\u0004\u0001\u0000\u0000\u0000&\'\u0005<\u0000\u0000"+
        "\'\u0006\u0001\u0000\u0000\u0000()\u0005<\u0000\u0000)*\u0005=\u0000\u0000"+
        "*\b\u0001\u0000\u0000\u0000+,\u0005=\u0000\u0000,-\u0005=\u0000\u0000"+
        "-\n\u0001\u0000\u0000\u0000./\u0005c\u0000\u0000/0\u0005o\u0000\u0000"+
        "01\u0005u\u0000\u000012\u0005n\u0000\u000023\u0005t\u0000\u00003\f\u0001"+
        "\u0000\u0000\u000045\u0005s\u0000\u000056\u0005u\u0000\u000067\u0005m"+
        "\u0000\u00007\u000e\u0001\u0000\u0000\u000089\u0005m\u0000\u00009:\u0005"+
        "i\u0000\u0000:;\u0005n\u0000\u0000;\u0010\u0001\u0000\u0000\u0000<=\u0005"+
        "m\u0000\u0000=>\u0005a\u0000\u0000>?\u0005x\u0000\u0000?\u0012\u0001\u0000"+
        "\u0000\u0000@A\u0005a\u0000\u0000AB\u0005v\u0000\u0000BC\u0005g\u0000"+
        "\u0000C\u0014\u0001\u0000\u0000\u0000DE\u0005b\u0000\u0000EF\u0005y\u0000"+
        "\u0000F\u0016\u0001\u0000\u0000\u0000GH\u0005(\u0000\u0000H\u0018\u0001"+
        "\u0000\u0000\u0000IJ\u0005)\u0000\u0000J\u001a\u0001\u0000\u0000\u0000"+
        "KM\u0005-\u0000\u0000LK\u0001\u0000\u0000\u0000LM\u0001\u0000\u0000\u0000"+
        "MO\u0001\u0000\u0000\u0000NP\u0007\u0000\u0000\u0000ON\u0001\u0000\u0000"+
        "\u0000PQ\u0001\u0000\u0000\u0000QO\u0001\u0000\u0000\u0000QR\u0001\u0000"+
        "\u0000\u0000RY\u0001\u0000\u0000\u0000SU\u0005.\u0000\u0000TV\u0007\u0000"+
        "\u0000\u0000UT\u0001\u0000\u0000\u0000VW\u0001\u0000\u0000\u0000WU\u0001"+
        "\u0000\u0000\u0000WX\u0001\u0000\u0000\u0000XZ\u0001\u0000\u0000\u0000"+
        "YS\u0001\u0000\u0000\u0000YZ\u0001\u0000\u0000\u0000Z\u001c\u0001\u0000"+
        "\u0000\u0000[_\u0007\u0001\u0000\u0000\\^\u0007\u0002\u0000\u0000]\\\u0001"+
        "\u0000\u0000\u0000^a\u0001\u0000\u0000\u0000_]\u0001\u0000\u0000\u0000"+
        "_`\u0001\u0000\u0000\u0000`\u001e\u0001\u0000\u0000\u0000a_\u0001\u0000"+
        "\u0000\u0000bd\u0007\u0003\u0000\u0000cb\u0001\u0000\u0000\u0000de\u0001"+
        "\u0000\u0000\u0000ec\u0001\u0000\u0000\u0000ef\u0001\u0000\u0000\u0000"+
        "fg\u0001\u0000\u0000\u0000gh\u0006\u000f\u0000\u0000h \u0001\u0000\u0000"+
        "\u0000\u0007\u0000LQWY_e\u0001\u0006\u0000\u0000";
    public static final ATN _ATN =
        new ATNDeserializer().deserialize(_serializedATN.toCharArray());
    static {
        _decisionToDFA = new DFA[_ATN.getNumberOfDecisions()];
        for (int i = 0; i < _ATN.getNumberOfDecisions(); i++) {
            _decisionToDFA[i] = new DFA(_ATN.getDecisionState(i), i);
        }
    }
}