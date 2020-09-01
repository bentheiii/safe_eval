from pytest import fixture

from safe_eval import SafeEval


@fixture
def assert_eval():
    se = SafeEval()

    def ret(s: str, e):
        evaluated = se(s)
        assert evaluated == e

    return ret


def test_literal(assert_eval):
    assert_eval("12", 12)
    assert_eval("'1+2'", '1+2')
    assert_eval("15.5", 15.5)


def test_list(assert_eval):
    assert_eval('[1,2]', [1, 2])
    assert_eval('(1)', 1)
    assert_eval('1,', (1,))


def test_op(assert_eval):
    assert_eval('2 in ["1","2"]', False)
    assert_eval('(1+2.3)**2', 3.3 ** 2)
    assert_eval('1<2<3', True)
    assert_eval('() if range(15) else []', ())


def test_functions(assert_eval):
    assert_eval('bool([dict])', True)
    assert_eval('sum(range(7))', 21)


def test_method(assert_eval):
    assert_eval('"-".join("012")', '0-1-2')


def test_comp(assert_eval):
    assert_eval('[str(i) for i in range(3)]', ["0", "1", "2"])
    assert_eval('",".join([str(i) for i in range(3)])', '0,1,2')
