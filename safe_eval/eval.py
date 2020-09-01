from __future__ import annotations

from _ast import Expr, Name, Call, Starred, Constant, BinOp, Compare, UnaryOp, BoolOp, Attribute, FormattedValue,\
    cmpop, operator as binop, unaryop, \
    List, Tuple, Set, \
    Add, Sub, Mult, MatMult, Div, Mod, Pow, LShift, RShift, BitOr, BitXor, BitAnd, FloorDiv, \
    Invert, Not, UAdd, USub, \
    And, \
    Eq, NotEq, Lt, LtE, Gt, GtE, Is, IsNot, In, NotIn, Dict
from collections import ChainMap, deque
from typing import NamedTuple, Any, Dict as tDict, Mapping, Deque, Optional, Callable, \
    TypeVar, Type, Union, Iterable, Sequence
import operator as op

from safe_eval.errors import UnauthorizedNameAccess, UnauthorizedCall, UnauthorizedAttributeAccess

iterable_literals = {
    List: list,
    Tuple: tuple,
    Set: set
}
binary_ops = {
    Add: op.add, Sub: op.sub, Mult: op.mul, MatMult: op.matmul, Div: op.truediv, Mod: op.mod, Pow: op.pow,
    LShift: op.lshift, RShift: op.rshift, BitOr: op.or_, BitXor: op.xor, BitAnd: op.and_, FloorDiv: op.floordiv
}
unary_ops = {
    Invert: op.inv, Not: op.not_, UAdd: op.pos, USub: op.neg
}
comparisons = {
    Eq: op.eq, NotEq: op.ne, Lt: op.lt, LtE: op.le, Gt: op.gt, GtE: op.ge, Is: op.is_, IsNot: op.is_not,
    In: lambda x, y: x in y, NotIn: lambda x, y: x not in y
}

T = TypeVar('T')
Rule = Callable[[T], Optional[bool]]


class CallAttempt(NamedTuple):
    func: Callable
    args: Sequence
    kwargs: tDict[str, Any]


class GetattrAttempt(NamedTuple):
    owner: Any
    attr: str


class BinOpAttempt(NamedTuple):
    left: Any
    right: Any
    operator: Union[Type[cmpop], Type[binop]]


class UOpAttempt(NamedTuple):
    operand: Any
    operator: Type[unaryop]

def _authorize(attempt: T, rules: Iterable[Rule[T]]):
    for rule in rules:
        ret = rule(attempt)
        if ret is not None:
            return ret
    return False


class SafeEval:
    def __init__(self):
        self.call_rules: Deque[Rule[CallAttempt]] = deque()
        self.getattr_rules: Deque[Rule[GetattrAttempt]] = deque()
        self.binop_rules: Deque[Rule[BinOpAttempt]] = deque()
        self.uop_rules: Deque[Rule[UOpAttempt]] = deque()

        self.static_vars: tDict[str, Any] = {}

    def call_authorized(self, attempt: CallAttempt):
        return _authorize(attempt, self.call_rules)

    def getattr_authorized(self, attempt: GetattrAttempt):
        return _authorize(attempt, self.getattr_rules)

    def binop_authorized(self, attempt: BinOpAttempt):
        return _authorize(attempt, self.binop_rules)

    def uop_authorized(self, attempt: UOpAttempt):
        return _authorize(attempt, self.uop_rules)


class Evaluation:
    def __init__(self, owner: SafeEval, free_vars: Mapping[str, Any]):
        self.owner = owner
        self.free_vars = free_vars
        self.vars = ChainMap(self.free_vars, self.owner.static_vars)

    def _assert_hash_authorized(self, obj):
        func = obj.__hash__
        attempt = CallAttempt(func, (), {})
        if not self.owner.call_authorized(attempt):
            raise UnauthorizedCall(attempt)

    def _handle_expr(self, expr: Expr):
        if isinstance(expr, Constant):
            return expr.value
        if isinstance(expr, Name):
            if expr.id not in self.vars:
                raise UnauthorizedNameAccess(expr.id)
            return self.vars[expr.id]
        if isinstance(expr, Call):
            func = self._handle_expr(expr.func)

            args = []
            for arg in expr.args:
                if isinstance(arg, Starred):
                    v = self._handle_expr(arg.value)
                    args.extend(v)
                else:
                    v = self._handle_expr(arg)
                    args.append(v)
            kwargs = {}
            for kw in expr.keywords:
                v = self._handle_expr(kw.value)
                if kw.arg is None:
                    # double starred
                    pre_len = len(kwargs)
                    kwargs.update(v)
                    if len(kwargs) != pre_len + len(v):
                        raise TypeError('multiple values for keyword arguments')
                elif kw.arg in kwargs:
                    raise TypeError('multiple values for keyword arguments')
                else:
                    kwargs[kw.arg] = v
            attempt = CallAttempt(func, args, kwargs)
            if not self.owner.call_authorized(attempt):
                raise UnauthorizedCall(attempt)
            return func(*args, **kwargs)
        if isinstance(expr, BinOp):
            operator = binary_ops[type(expr.op)]
            left = self._handle_expr(expr.left)
            right = self._handle_expr(expr.right)
            attempt = BinOpAttempt(left, right, type(expr.op))
            if not self.owner.binop_authorized(attempt):
                raise UnauthorizedCall(attempt)
            return operator(left, right)
        if isinstance(expr, UnaryOp):
            operator = unary_ops[type(expr.op)]
            operand = self._handle_expr(expr.operand)
            attempt = UOpAttempt(type(expr.op), operand)
            if not self.owner.uop_authorized(attempt):
                raise UnauthorizedCall(attempt)
            return operator(operand)
        if isinstance(expr, BoolOp):
            if isinstance(expr.op, And):
                for e in expr.values:
                    ret = self._handle_expr(e)
                    if not ret:
                        return ret
                return ret
            else:
                # or
                for e in expr.values:
                    ret = self._handle_expr(e)
                    if ret:
                        return ret
                return ret
        if isinstance(expr, Compare):
            operands = [expr.left, *expr.comparators]
            for (left, operator, right) in zip(operands, expr.ops, operands[1:]):
                left = self._handle_expr(left)
                right = self._handle_expr(right)
                operator_py = comparisons[type(operator)]
                attempt = BinOpAttempt(left, right, type(operator))
                if not self.owner.binop_authorized(attempt):
                    raise UnauthorizedCall(attempt)
                ret = operator_py(left, right)
                if not ret:
                    return ret
            return ret
        if isinstance(expr, Attribute):
            obj = self._handle_expr(expr.value)
            attr = expr.attr
            attempt = GetattrAttempt(obj, attr)
            if not self.owner.getattr_authorized(attempt):
                raise UnauthorizedAttributeAccess(attempt)
            return getattr(obj, attr)
        if isinstance(expr, Dict):
            ret = {}
            for k_expr, v_expr in zip(expr.keys, expr.values):
                key = self._handle_expr(k_expr)
                self._assert_hash_authorized(key)
                value = self._handle_expr(v_expr)
                ret[key] = value
            return ret
        if isinstance(expr, FormattedValue):
            inner = self._handle_expr(expr.value)
        iterable_literal = iterable_literals.get(type(expr))
        if iterable_literal:
            ret = []
            for elt in expr.elts:
                if isinstance(elt, Starred):
                    v = self._handle_expr(elt.value)
                    ret.extend(v)
                else:
                    v = self._handle_expr(elt)
                    ret.append(v)
            if iterable_literal is set:
                for r in ret:
                    self._assert_hash_authorized(r)
            return iterable_literal(ret)

        # todo comprehensions?

        raise TypeError
