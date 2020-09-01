from _ast import cmpop, operator, unaryop
from typing import TypeVar, Callable, Optional, NamedTuple, Sequence, Dict, Any, Union, Type

T = TypeVar('T')
Rule = Callable[[T], Optional[bool]]


class CallAttempt(NamedTuple):
    func: Callable
    args: Sequence
    kwargs: Dict[str, Any]


class GetattrAttempt(NamedTuple):
    owner: Any
    attr: str


class BinOpAttempt(NamedTuple):
    left: Any
    right: Any
    operator: Union[Type[cmpop], Type[operator]]


class UOpAttempt(NamedTuple):
    operand: Any
    operator: Type[unaryop]


class SubscriptAttempt(NamedTuple):
    owner: Any
    args: Any
