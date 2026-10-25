"""Pure output comparisons, NEVER candidate execution or official-harness import.

The standard-output rule is adapted from MIT-licensed LiveCodeBench commit
28fef95ea8c9f7a547c8329f2cd3d32b92c1fa24, testing_util.py grade_stdio,
get_stripped_lines and convert_line_to_decimals. See licenses/LiveCodeBench-MIT.txt.
"""
from decimal import Context,Decimal,InvalidOperation,localcontext
import json

REFERENCE_COMMIT='28fef95ea8c9f7a547c8329f2cd3d32b92c1fa24'
REFERENCE_SHA256='b7cb6a8a69807bb868150a61742e25d7bb5328bbe01d514471b6ec43c9fa9ed2'
MAX_TEXT_BYTES=65536


def project_compare(actual,expected,kind):
    """Recompute the existing project rule; tested against lcb_sandbox.compare."""
    if kind=='whitespace_tokens_exact':return actual.split()==expected.split()
    if kind=='json_exact':
        try:
            return json.dumps(json.loads(actual),sort_keys=True,allow_nan=False)==json.dumps(json.loads(expected),sort_keys=True,allow_nan=False)
        except (ValueError,TypeError):return False
    raise ValueError('Unknown project comparison rule')


def compare_stdout(actual,expected):
    """Supported finite numeric branch only. No special judge or fuzzy epsilon."""
    if not isinstance(actual,str) or not isinstance(expected,str):raise ValueError('Output strings required')
    if max(len(actual.encode()),len(expected.encode()))>MAX_TEXT_BYTES:
        return {'status':'unsupported','reason':'text_size_limit','pass':None}
    left=[line.strip() for line in actual.strip().split('\n')]
    right=[line.strip() for line in expected.strip().split('\n')]
    if len(left)!=len(right):return {'status':'compared','pass':False,'reason':'line_count_mismatch'}
    with localcontext(Context()):
        for index,(a,b) in enumerate(zip(left,right)):
            if a==b:continue
            try:
                aa=[Decimal(x) for x in a.split()];bb=[Decimal(x) for x in b.split()]
            except (InvalidOperation,ValueError):
                return {'status':'compared','pass':False,'reason':'unequal_nonnumeric_line','line_index':index}
            if any(not x.is_finite() for x in aa+bb):
                return {'status':'unsupported','pass':None,'reason':'nonfinite_numeric_comparison','line_index':index}
            if aa!=bb:return {'status':'compared','pass':False,'reason':'exact_decimal_mismatch','line_index':index}
    return {'status':'compared','pass':True,'reason':'all_lines_equal'}
