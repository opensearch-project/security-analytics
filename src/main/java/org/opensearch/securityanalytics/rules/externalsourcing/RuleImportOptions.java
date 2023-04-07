package org.opensearch.securityanalytics.rules.externalsourcing;

import java.util.EnumSet;
import org.opensearch.action.support.IndicesOptions;

public class RuleImportOptions {

    public enum Option {
        IGNORE_DELETED_FROM_SOURCE,
        OVERWRITE_MODIFIED,
        IGNORE_MODIFIED;

        public static final EnumSet<Option> NONE = EnumSet.noneOf(Option.class);
    }

    public static final RuleImportOptions OVERWRITE_MODIFIED_IGNORE_DELETED = new RuleImportOptions(
            EnumSet.of(Option.OVERWRITE_MODIFIED, Option.IGNORE_DELETED_FROM_SOURCE)
    );

    private final EnumSet<Option> options;

    public RuleImportOptions(EnumSet<Option> options) {
        this.options = options;
    }

    public boolean ignoreDeletedFromSource() {
        return options.contains(Option.IGNORE_DELETED_FROM_SOURCE);
    }
    public boolean overwriteModified() {
        return options.contains(Option.OVERWRITE_MODIFIED);
    }
    public boolean ignoreModified() {
        return options.contains(Option.IGNORE_MODIFIED);
    }


    public static RuleImportOptions fromOptions(
            boolean ignoreDeletedFromSource,
            boolean overwriteModified,
            boolean ignoreModified
    ) {
        final EnumSet<Option> opts = EnumSet.noneOf(Option.class);

        if (ignoreDeletedFromSource) {
            opts.add(Option.IGNORE_DELETED_FROM_SOURCE);
        }
        if (overwriteModified) {
            opts.add(Option.OVERWRITE_MODIFIED);
        }
        if (ignoreModified) {
            opts.add(Option.IGNORE_MODIFIED);
        }
        return new RuleImportOptions(opts);
    }
}
