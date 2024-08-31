import logging
import re
from boolean import boolean
from sqlalchemy import String

from app.domain import ParsedSearchString
from app.models import db
from app.routes.utils_db import VersionPicker

logger = logging.getLogger(__name__)

def parse_search_str(search: str, joiner: str = "&") -> ParsedSearchString:
    """Converts a boolean search string into a boolean expression

    search: a user-entered search string that can include boolean operators, prefix-matching, and quoted phrases
    joiner: boolean operator to combine adjacent terms with
    - '&' AND is default
    - '|' OR is also an option

    sets ParsedSearchString.error if the boolean expression is invalid or if there isn't at least one a-zA-Z0-9 term
    """

    term_pattern = r'("[^"]+"\*?|[^\(\)\|\&\~"\* ]+\*?)'

    # pull terms from search string and process
    terms = re.findall(term_pattern, search)
    sym_to_term = {}
    for num, t in enumerate(terms):
        # note if prefix-matching enabled, remove indicator if present
        prefix = t[-1] == "*"
        if prefix:
            t = t[:-1]

        # remove quotes if term was quoted
        if t[0] == '"':
            t = t[1:-1]

        # remove and collapse any non-alphanumerics, Error on term with no alphanum content
        t = re.sub("[^A-Za-z0-9]+", " ", t).strip()
        if not t:
            return ParsedSearchString(error="Term must have at-least one A-Za-z0-9 character")

        # store term and if prefix-match is enabled
        sym_to_term[f"s{num}"] = (t, prefix)

    # replace all terms with 's', then remove any spaces
    expr = re.sub(term_pattern, "s", search)
    expr = re.sub(" +", "", expr)

    # replace all 's' with 's0', 's1', .., 'sN'
    lexpr = list(expr)
    num = 0
    for ind, char in enumerate(lexpr):
        if char == "s":
            lexpr[ind] = f"s{num}"
            num += 1
    expr = "".join(lexpr)

    # insert & between adjacent symbols / parents, 2 times for trivial overlap handling
    for _ in range(2):
        expr = re.sub(r"(s[0-9]+)(~?s[0-9]+)", rf"\1{joiner}\2", expr)  # SymSym -> Sym&Sym
        expr = re.sub(r"(s[0-9]+)(~?\()", rf"\1{joiner}\2", expr)  # Sym( -> Sym&(
        expr = re.sub(r"(\))(~?s[0-9]+)", rf"\1{joiner}\2", expr)  # )Sym -> )&Sym
        expr = re.sub(r"(\))(~?\()", rf"\1{joiner}\2", expr)  # )( -> )&(

    # collapse double negatives
    while "~~" in expr:
        expr = expr.replace("~~", "")

    # attempt to interpret search expression in boolean alg library
    try:
        bool_expr = boolean.BooleanAlgebra().parse(expr)
    except Exception:
        return ParsedSearchString(error="Search query is formatted improperly")

    return ParsedSearchString(bool_expr=bool_expr, sym_to_term=sym_to_term)


def tsqry_rep(bexpr, sym_terms):
    """Creates a ts_query representation from the output of parse_search_str(sstr)

    Input: (bool_expr, sym_to_term)
    - see what parse_search_str(sstr) returns for info on this tuple

    returns a string that is valid PostgreSQL which forms a ts_query of the search string
    """

    # base symbol
    if isinstance(bexpr, boolean.Symbol):
        term, prefix = sym_terms[bexpr.obj]

        # is a phrase, join with <->, add prefix-match to all parts if specified
        if " " in term:
            term = " <-> ".join(f'{part}{":*" if prefix else ""}' for part in term.split())

        # is a single word, add prefix-match if specified
        else:
            term = f'{term}{":*" if prefix else ""}'

        escaped_term = String("").literal_processor(dialect=db.session.get_bind().dialect)(value=term)
        return f"to_tsquery('english_nostop', {escaped_term})"

    # and together
    elif isinstance(bexpr, boolean.AND):
        anded = " && ".join(tsqry_rep(sym, sym_terms) for sym in bexpr.args)
        return f"({anded})"

    # or together
    elif isinstance(bexpr, boolean.OR):
        ored = " || ".join(tsqry_rep(sym, sym_terms) for sym in bexpr.args)
        return f"({ored})"

    # negate
    elif isinstance(bexpr, boolean.NOT):
        return f"!!({tsqry_rep(bexpr.args[0], sym_terms)})"


def plain_rep(bexpr, sym_terms):
    """Creates a human-readable representation from the output of parse_search_str(sstr)

    closely related to tsqry_rep(bexpr, sym_terms):
    - this generates a string for a human to read.
    - tsqry_rep generates a string for PostgreSQL to read.

    Input: (bool_expr, sym_to_term)
    - see what parse_search_str(sstr) returns for info on this tuple

    returns a string that is a human-readable boolean search expression based on the search string they entered
    - this string is presented under the full Technique search entry box
    - showing the user how the expression was interpreted could help with issues regarding boolean order-of-operations
    - showing how the expression is interpreted also gives the user insight into how text is broke into tokens
    """

    # INPUT: (output of parse_search_str, this also recurses)
    # OUTPUT: a human-readable string of the search used internally

    # base symbol
    if isinstance(bexpr, boolean.Symbol):
        term, prefix = sym_terms[bexpr.obj]

        # is a phrase, join with <->, add prefix-match to all parts if specified
        if " " in term:
            term = " ".join(f'{part}{"*" if prefix else ""}' for part in term.split())
            term = f'"{term}"'

        # is a single word, add prefix-match if specified
        else:
            term = f'{term}{"*" if prefix else ""}'

        return term

    # and together
    elif isinstance(bexpr, boolean.AND):
        anded = " & ".join(plain_rep(sym, sym_terms) for sym in bexpr.args)
        return f"({anded})"

    # or together
    elif isinstance(bexpr, boolean.OR):
        ored = " | ".join(plain_rep(sym, sym_terms) for sym in bexpr.args)
        return f"({ored})"

    # negate
    elif isinstance(bexpr, boolean.NOT):
        return "~" + plain_rep(bexpr.args[0], sym_terms)

def technique_search_args_are_valid(version, query, tactics, mitigation_sources, platforms, data_sources):
    """Validates the attempted arguments for a technique search request

    - pulled-out to prevent an overly-long function

    returns bool on if the arguments pass or not
    """

    # required fields missing
    if (version is None) or (query is None):
        logger.error("request malformed - missing required field(s)")
        return False

    # check version validity & get DB model
    version_pick = VersionPicker(version=version)
    if not version_pick.is_valid:
        logger.error("request malformed - version specified isn't on server")
        return False
    ver_model = version_pick.cur_version_model

    # ensure that specified tactics exist
    logger.debug(f"querying Tactics in ATT&CK {version} (to validate request)")
    valid_tactics = {t.tact_name.replace(" ", "_").lower() for t in ver_model.tactics}
    specified_tactics = set(tactics)
    if len(specified_tactics) != len(specified_tactics.intersection(valid_tactics)):
        logger.error("request malformed - tactic(s) specified aren't in version")
        return False

    # ensure that specified mitigation Sources exist
    logger.debug(f"querying Mitigation Sources in ATT&CK {version} (to validate request)")
    #############################################
    #############################################
    ## Needs to come from the database
    ## Will require an update to the db import to
    ## include the Mitigation_Source table
    valid_mitigation_sources = ['ism', 'mitre', 'nist']
    #############################################
    #############################################
    
    specified_mitigation_sources = set(mitigation_sources)
    if len(specified_mitigation_sources) != len(specified_mitigation_sources.intersection(valid_mitigation_sources)):
        logger.error("request malformed - mitigation Source(s) specified aren't in version")
        return False

    # ensure that specified platforms exist
    logger.debug(f"querying Platforms in ATT&CK {version} (to validate request)")
    valid_platforms = {p.internal_name for p in ver_model.platforms}
    specified_platforms = set(platforms)
    if len(specified_platforms) != len(specified_platforms.intersection(valid_platforms)):
        logger.error("request malformed - platform(s) specified aren't in version")
        return False

    # ensure that specified data sources exist
    logger.debug(f"querying Data Sources in ATT&CK {version} (to validate request)")
    valid_data_sources = {s.internal_name for s in ver_model.data_sources}
    specified_data_sources = set(data_sources)
    if len(specified_data_sources) != len(specified_data_sources.intersection(valid_data_sources)):
        logger.error("request malformed - data source(s) specified aren't in version")
        return False

    return True  # all passed
