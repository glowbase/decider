from dataclasses import dataclass
from typing import Dict, Tuple, Union
from boolean import boolean

@dataclass
class ParsedSearchString:
    """
    Represents a parsed search string
    - (parse success) holds a boolean representation of the search and a symbol lookup table
    - (parse failure) holds a string explaining the parse issue
    - bool_expr is a BooleanAlgebra expression of symbols 's0', 's1',.. 'sN' (easy to process recursively)
    - sym_to_term is a dict mapping symbols to search terms and if they're prefix-matched 's0' -> ('bios', False)
    """

    # success
    bool_expr: Union[boolean.Expression, None] = None
    sym_to_term: Union[Dict[str, Tuple[str, bool]], None] = None

    # failure
    error: Union[str, None] = None
