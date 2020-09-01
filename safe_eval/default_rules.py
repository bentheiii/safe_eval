from _ast import In, NotIn, Is, IsNot
from collections import deque, Counter
from decimal import Decimal
from fractions import Fraction

from safe_eval.rules import BinOpRule, CallableTypeRule, CallableRule, GetattrTypeRule, CallableMethodRule

k_view_type = type({}.keys())
v_view_type = type({}.values())
it_view_type = type({}.items())
trusted_iterator_types = set(
    type(iter(t())) for t in (str, tuple, bytes, list, set, frozenset, dict, deque, Counter)
)
trusted_iterator_types.update((
    type(iter({}.keys())),
    type(iter({}.values())),
    type(iter({}.items())),
    type(iter(range(0))),
))

immutable_trusted = frozenset((int, bool, float, str, complex, frozenset, tuple, Decimal, Fraction, bytes, type(None),
                               type(...), type(NotImplemented), object, range))
mutable_trusted = frozenset((list, set, dict, k_view_type, v_view_type, it_view_type, Exception, NameError,
                             ValueError, LookupError, KeyError, TypeError, deque, Counter, *trusted_iterator_types))

trusted_types = immutable_trusted | mutable_trusted
trusted_types |= trusted_iterator_types

bin_op_trusted_types = trusted_types

default_bin_rules = [
    BinOpRule(..., op_set=(Is, IsNot)),
    BinOpRule(bin_op_trusted_types),
    BinOpRule(..., bin_op_trusted_types, (In, NotIn))
]

trusted_builtin_unary_funcs = frozenset((
    abs, all, any, ascii,
    bin, bool, bytearray, bytes,
    chr, complex,
    dict,
    enumerate,
    float, format, frozenset,
    hasattr, hash, hex,
    int, iter,
    len, list,
    max, min,
    next,
    oct,
    property,
    range, repr, reversed, round,
    set, slice, sorted, str, sum,
    tuple, zip,
))

safe_builtin_unary_funcs = frozenset((
    id,
    callable, classmethod,
    ord,
))

# todo a lot of functions are only fine if iteration is fine, do that

default_callable_rules = [
    CallableTypeRule(trusted_builtin_unary_funcs, trusted_types),
    CallableTypeRule(safe_builtin_unary_funcs, ...),
    CallableTypeRule(divmod, trusted_types, trusted_types),
    CallableRule((isinstance, issubclass), ..., trusted_types),
    CallableRule(object),
    CallableTypeRule(pow, trusted_types, trusted_types, trusted_types)
]

imported_builtin_names = {*trusted_builtin_unary_funcs, *safe_builtin_unary_funcs,
                          divmod, isinstance, issubclass, object, pow}
default_namespace = {ibn.__name__: ibn for ibn in imported_builtin_names}

default_attr_rules = []


def _allow_method(owner, method, *args, **kwargs):
    if isinstance(method, str):
        method_name = method
        method = getattr(owner, method)
    else:
        method_name = method.__name__
    default_attr_rules.append(GetattrTypeRule(owner, method_name))
    default_callable_rules.append(CallableMethodRule(method, owner, *args, **kwargs))


_allow_method(str, str.join, trusted_types)
