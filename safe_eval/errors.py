class UnauthorizedEvalError(ValueError):
    pass


class UnauthorizedNameAccess(UnauthorizedEvalError, NameError):
    pass


class UnauthorizedCall(UnauthorizedEvalError):
    pass


class UnauthorizedAttributeAccess(UnauthorizedEvalError):
    pass
