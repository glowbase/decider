class PSQLTxt:
    """Set of PostgreSQL (+ general) text functions for succinct composition of queries"""

    @staticmethod
    def no_html(txt):
        return rf"regexp_replace({txt}, '<\/?(sup|a|code)[^>]*>', '', 'gi')"

    @staticmethod
    def no_md_urls(txt):
        return rf"regexp_replace({txt}, '\[([^\]]+)\]\([^\)]+\)', '\1', 'gi')"

    @staticmethod
    def unaccent(txt):
        return f"unaccent({txt})"

    @staticmethod
    def only_alnum(txt):
        return f"regexp_replace({txt}, '[^a-z0-9 ]+', ' ', 'gi')"

    @staticmethod
    def to_tsvec(txt):
        return f"to_tsvector('english_nostop', {txt})"

    @staticmethod
    def concat_spaced(txts):
        return " || ' ' || ".join(txts)

    @staticmethod
    def zwspace_pad_special(txt):
        """Surrounds runs of special characters with hair-spaces
            - Splits on specials as a form of tokenization
            - Minimally alters visual output
        """
        return f"regexp_replace({txt}, '([^a-z0-9 ]+)', '\u200A\\1\u200A', 'gi')"

    @staticmethod
    def basic_headline(txt, qry):
        return f"ts_headline('english_nostop', {txt}, {qry}, 'HighlightAll=true,StartSel=<mark>,StopSel=</mark>')"

    @staticmethod
    def no_citation_nums(txt):
        return rf"regexp_replace({txt}, '\[[0-9]{{1,2}}\]', '', 'gi')"

    @staticmethod
    def newlines_as_space(txt):
        return rf"regexp_replace({txt}, '(\n)+', ' ', 'gi')"

    @staticmethod
    def multiline_cleanup(qry):
        stripped_lines = [ln.strip() for ln in qry.split("\n")]
        nonempty_lines = [ln for ln in stripped_lines if ln]
        return "".join(nonempty_lines)

