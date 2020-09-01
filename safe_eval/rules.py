from inspect import getattr_static
from typing import Container, NamedTuple, Any

from safe_eval.attempt_model import BinOpAttempt, CallAttempt, GetattrAttempt


def _passes_constraint(arg, constraint):
    return constraint is ... \
           or arg == constraint \
           or (isinstance(constraint, Container) and arg in constraint)


class BinOpRule:
    def __init__(self, right_supertype, left_supertype=None, op_set: Container = ...):
        self.right = right_supertype
        self.left = left_supertype or self.right
        self.op_set = op_set

    def __call__(self, attempt: BinOpAttempt):
        if _passes_constraint(type(attempt.right), self.right) \
                and _passes_constraint(type(attempt.left), self.left) \
                and _passes_constraint(attempt.operator, self.op_set):
            return True


class Optional(NamedTuple):
    inner: Any


class CallableTypeRule:
    def __init__(self, func: callable, *optional_positional, **optional_kw):
        self.func = func
        self.optional_positional = optional_positional
        self.optional_kw = optional_kw

    def __call__(self, attempt: CallAttempt):
        if not _passes_constraint(attempt.func, self.func):
            return None
        if len(attempt.args) > len(self.optional_positional):
            return None
        if not all(_passes_constraint(type(a), c) for (a, c) in zip(attempt.args, self.optional_positional)):
            return None
        for k, v in attempt.kwargs.items():
            c = self.optional_kw.get(k)
            if not c:
                return None
            if not _passes_constraint(type(v), c):
                return None
        return True


bound_method_type = type(''.join)


class CallableMethodRule(CallableTypeRule):
    def __call__(self, attempt: CallAttempt):
        if type(attempt.func) is not bound_method_type:
            return None
        # todo get these statically
        owner = attempt.func.__self__
        if not _passes_constraint(type(owner), self.optional_positional[0]):
            return None
        func = getattr_static(attempt.func, '__func__', None) or getattr_static(type(owner), attempt.func.__name__)
        new_attempt = CallAttempt(func, (owner, *attempt.args), attempt.kwargs)
        return super().__call__(new_attempt)


class CallableRule:
    def __init__(self, func: callable, *optional_positional, **optional_kw):
        self.func = func
        self.optional_positional = optional_positional
        self.optional_kw = optional_kw

    def __call__(self, attempt: CallAttempt):
        if not _passes_constraint(attempt.func, self.func):
            return None
        if len(attempt.args) > len(self.optional_positional):
            return None
        if not all(_passes_constraint(a, c) for (a, c) in zip(attempt.args, self.optional_positional)):
            return None
        for k, v in attempt.kwargs.items():
            c = self.optional_kw.get(k)
            if not c:
                return None
            if not _passes_constraint(v, c):
                return None
        return True


class GetattrTypeRule:
    def __init__(self, owner, attrs):
        self.owner = owner
        self.attrs = attrs

    def __call__(self, attempt: GetattrAttempt):
        if _passes_constraint(type(attempt.owner), self.owner) and _passes_constraint(attempt.attr, self.attrs):
            return True


class GetattrRule:
    def __init__(self, owner, attrs):
        self.owner = owner
        self.attrs = attrs

    def __call__(self, attempt: GetattrAttempt):
        if _passes_constraint(attempt.owner, self.owner) and _passes_constraint(attempt.attr, self.attrs):
            return True
