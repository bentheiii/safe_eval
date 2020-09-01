from __future__ import annotations

import operator as op
from _ast import Name, Call, Starred, Constant, BinOp, Compare, UnaryOp, BoolOp, Attribute, FormattedValue, \
    JoinedStr, IfExp, Lambda, Subscript, \
    ListComp, SetComp, GeneratorExp, \
    DictComp, \
    expr, \
    List, Tuple, Set, \
    Add, Sub, Mult, MatMult, Div, Mod, Pow, LShift, RShift, BitOr, BitXor, BitAnd, FloorDiv, \
    Invert, Not, UAdd, USub, \
    And, \
    Eq, NotEq, Lt, LtE, Gt, GtE, Is, IsNot, In, NotIn, \
    Dict
from ast import parse
from collections import ChainMap, deque
from typing import Any, Dict as tDict, Mapping, Deque, TypeVar, Union, Iterable

from safe_eval.attempt_model import Rule, CallAttempt, GetattrAttempt, BinOpAttempt, UOpAttempt, SubscriptAttempt
from safe_eval.default_rules import default_bin_rules, default_callable_rules, default_namespace, default_attr_rules
from safe_eval.errors import UnauthorizedNameAccess, UnauthorizedCall, UnauthorizedAttributeAccess, \
    UnauthorizedEvalError, UnauthorizedSubscript

iterable_literals = {
    List: list,
    Tuple: tuple,
    Set: set
}
comprehension_iterables = {
    ListComp: list,
    SetComp: set,
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

def _authorize(attempt: T, rules: Iterable[Rule[T]]):
    for rule in rules:
        ret = rule(attempt)
        if ret is not None:
            return ret
    return False


class SafeEval:
    def __init__(self):
        self.call_rules: Deque[Rule[CallAttempt]] = deque(default_callable_rules)
        self.getattr_rules: Deque[Rule[GetattrAttempt]] = deque(default_attr_rules)
        self.binop_rules: Deque[Rule[BinOpAttempt]] = deque(default_bin_rules)
        self.uop_rules: Deque[Rule[UOpAttempt]] = deque()
        self.subscript_rules: Deque[Rule[SubscriptAttempt]] = deque()

        self.static_vars: tDict[str, Any] = dict(default_namespace)

    def call_authorized(self, attempt: CallAttempt):
        return _authorize(attempt, self.call_rules)

    def getattr_authorized(self, attempt: GetattrAttempt):
        return _authorize(attempt, self.getattr_rules)

    def binop_authorized(self, attempt: BinOpAttempt):
        return _authorize(attempt, self.binop_rules)

    def uop_authorized(self, attempt: UOpAttempt):
        return _authorize(attempt, self.uop_rules)

    def subscript_authorized(self, attempt: SubscriptAttempt):
        return _authorize(attempt, self.subscript_rules)

    def __call__(self, s: str):
        evaluator = Evaluation(self, {})
        return evaluator(s)


class Evaluation:
    def __init__(self, owner: SafeEval, free_vars: Mapping[str, Any]):
        self.owner = owner
        self.free_vars = free_vars
        self.vars = ChainMap(self.free_vars, self.owner.static_vars)

    def with_var(self, new_vars: Mapping[str, Any]):
        return type(self)(self.owner, ChainMap(self.free_vars, new_vars))

    def _assert_call_authorized(self, func, *args, **kwargs):
        attempt = CallAttempt(func, args, kwargs)
        if not self.owner.call_authorized(attempt):
            raise UnauthorizedCall(attempt)

    def _evaluators_from_generator(self, expr: Union[ListComp, SetComp, DictComp]):
        iterator_stack = []
        gen = expr.generators[0]
        iterable = self._handle_expr(gen.iter)
        self._assert_call_authorized(iter, iterable)
        iterator_stack.append(iter(iterable))
        variables = {}
        sub_evaluation = self
        while iterator_stack:
            if len(iterator_stack) < len(expr.generators):
                last_generator = expr.generators[len(iterator_stack) - 1]
                last_iter = iterator_stack[-1]
                self._assert_call_authorized(next, last_iter)
                target_id = last_generator.target.id
                try:
                    variables[target_id] = next(last_iter)
                except StopIteration:
                    variables.pop(target_id, None)
                    iterator_stack.pop()
                else:
                    sub_evaluation = self.with_var(variables)
                    for condition in expr.ifs:
                        test = sub_evaluation._handle_expr(condition)
                        self._assert_call_authorized(bool, test)
                        if not test:
                            break
                    else:
                        next_gen = expr.generators[len(iterator_stack)]
                        iterable = sub_evaluation._handle_expr(next_gen.iter)
                        self._assert_call_authorized(iter, iterable)
                        iterator_stack.append(iter(iterable))
            else:
                last_generator = expr.generators[len(iterator_stack) - 1]
                last_iter = iterator_stack[-1]
                target_id = last_generator.target.id
                self._assert_call_authorized(next, last_iter)
                try:
                    variables[target_id] = next(last_iter)
                except StopIteration:
                    variables.pop(target_id, None)
                    iterator_stack.pop()
                else:
                    sub_evaluation = self.with_var(variables)
                    yield sub_evaluation

    def _handle_expr(self, expr: expr):
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
                    self._assert_call_authorized(bool, ret)
                    if not ret:
                        return ret
                return ret
            else:
                # or
                for e in expr.values:
                    ret = self._handle_expr(e)
                    self._assert_call_authorized(bool, ret)
                    if ret:
                        return ret
                return ret
        if isinstance(expr, Compare):
            operands = [expr.left, *expr.comparators]
            for i, (left, operator, right) in enumerate(zip(operands, expr.ops, operands[1:])):
                left = self._handle_expr(left)
                right = self._handle_expr(right)
                operator_py = comparisons[type(operator)]
                attempt = BinOpAttempt(left, right, type(operator))
                if not self.owner.binop_authorized(attempt):
                    raise UnauthorizedCall(attempt)
                ret = operator_py(left, right)
                if i != len(expr.ops)-1:
                    self._assert_call_authorized(bool, ret)
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
                v = self._handle_expr(v_expr)
                if k_expr is None:
                    for k in v.keys():
                        self._assert_call_authorized(hash, k)
                    ret.update(v)
                else:
                    k = self._handle_expr(k_expr)
                    self._assert_call_authorized(hash, k)
                    ret[k] = v
            return ret
        if isinstance(expr, FormattedValue):
            inner = self._handle_expr(expr.value)
            if expr.conversion != -1:
                conversion = {ord('r'): repr, ord('s'): str, ord('a'): ascii}[expr.conversion]
                self._assert_call_authorized(conversion, inner)
                inner = conversion(inner)
            if expr.format_spec:
                format_str = self._handle_expr(expr.format_spec)
                self._assert_call_authorized(format, inner, format_str)
                inner = format(inner, format_str)
            if not isinstance(inner, str):
                self._assert_call_authorized(str, inner)
                inner = str(inner)
            return inner
        if isinstance(expr, JoinedStr):
            return ''.join(self._handle_expr(v) for v in expr.values)
        if isinstance(expr, IfExp):
            cond = self._handle_expr(expr.test)
            self._assert_call_authorized(bool, cond)
            if cond:
                return self._handle_expr(expr.body)
            return self._handle_expr(expr.orelse)
        if isinstance(expr, DictComp):
            ret = {}
            for ev in self._evaluators_from_generator(expr):
                k = ev._handle_expr(expr.key)
                self._assert_call_authorized(hash, k)
                v = ev._handle_expr(expr.value)
                ret[k] = v
            return ret
        if isinstance(expr, Subscript):
            obj = self._handle_expr(expr.value)
            args = self._handle_expr(expr.slice)
            attempt = SubscriptAttempt(obj, args)
            if not self.owner.subscript_authorized(attempt):
                raise UnauthorizedSubscript(attempt)
            return obj[args]
        if isinstance(expr, (Lambda, GeneratorExp)):
            raise UnauthorizedEvalError('lazy elements and lambdas are not allowed')
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
                    self._assert_call_authorized(hash, r)
            return iterable_literal(ret)
        comprehension_iterable = comprehension_iterables.get(type(expr))
        if comprehension_iterable:
            ret = []
            for ev in self._evaluators_from_generator(expr):
                ret.append(ev._handle_expr(expr.elt))
            if comprehension_iterable is set:
                for r in ret:
                    self._assert_call_authorized(hash, r)
            return comprehension_iterable(ret)

        raise TypeError

    def __call__(self, arg: str):
        mod = parse(arg).body
        if len(mod) != 1:
            raise ValueError(f'argument has {len(mod)} statements, expected 1')
        return self._handle_expr(mod[0].value)
