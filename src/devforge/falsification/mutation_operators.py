"""Language-aware mutation operators for Python, built on the standard library.

Two decisions worth stating, because both were argued in the integration plan.

**Nothing external.** ``mutmut`` and ``cosmic-ray`` are mature, and both would be a
new runtime dependency in a tree whose dependency list is pinned by a passing
architecture test. Both also drive their own test-runner subprocesses, outside the
policy engine's argv allowlist, and one maintains its own session database - a
second state store. So the operators live here, behind DevForge's own interface, and
:class:`~devforge.falsification.strategies.mutation.MutationStrategy` is written so
an external backend can be plugged in later without the strategy changing.

**Nothing dynamic.** Mutants are produced by rewriting source *text* and are executed
by a subprocess. Nothing here calls ``compile`` or ``exec`` - forbidden by
``tests/test_architecture.py``, and the safer design regardless: a mutant is never
loaded into the process that generated it.

Mutation is deliberately conservative. An operator that produces mostly invalid or
mostly equivalent mutants wastes the budget that the useful operators needed, so each
one below refuses the cases it knows are degenerate rather than emitting a mutant and
letting the classifier sort it out.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

#: Operator identifiers, used in reports and in the benchmark oracles.
ARITHMETIC = "arithmetic_replacement"
COMPARISON = "comparison_replacement"
BOOLEAN = "boolean_replacement"
CONDITIONAL = "conditional_negation"
RETURN_VALUE = "return_value_mutation"
CONSTANT = "constant_replacement"
BOUNDARY = "boundary_mutation"
BRANCH = "branch_mutation"
EXCEPTION = "exception_path_mutation"

#: Which target each operator is evidence about. Mutating a comparison probes
#: boundary handling; removing a raise probes error handling.
OPERATOR_TARGETS = {
    ARITHMETIC: "behavior",
    COMPARISON: "boundary_conditions",
    BOOLEAN: "behavior",
    CONDITIONAL: "behavior",
    RETURN_VALUE: "behavior",
    CONSTANT: "behavior",
    BOUNDARY: "boundary_conditions",
    BRANCH: "behavior",
    EXCEPTION: "error_handling",
}

_ARITHMETIC_SWAPS: dict[type[ast.operator], type[ast.operator]] = {
    ast.Add: ast.Sub,
    ast.Sub: ast.Add,
    ast.Mult: ast.FloorDiv,
    ast.Div: ast.Mult,
    ast.FloorDiv: ast.Mult,
    ast.Mod: ast.Mult,
    ast.Pow: ast.Mult,
}

_COMPARISON_SWAPS: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
}

_OPERATOR_TEXT: dict[type, str] = {
    ast.Add: "+",
    ast.Sub: "-",
    ast.Mult: "*",
    ast.Div: "/",
    ast.FloorDiv: "//",
    ast.Mod: "%",
    ast.Pow: "**",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Is: "is",
    ast.IsNot: "is not",
    ast.In: "in",
    ast.NotIn: "not in",
    ast.And: "and",
    ast.Or: "or",
}


@dataclass(frozen=True)
class MutationCandidate:
    """One mutation that could be applied to one file.

    Carries the mutated *source text* rather than an AST, so applying it is a file
    write and running it is a subprocess - never an in-process import.
    """

    file: str
    line: int
    operator: str
    original: str
    mutated: str
    source: str
    target: str = "behavior"
    #: Column of the rewritten token within its line, or ``-1`` when the operator
    #: rewrote a whole expression rather than one token. The equivalence layers need
    #: it: a line can hold several operators, and reasoning about the wrong one is
    #: how a real surviving mutant gets dismissed as equivalent.
    col: int = -1

    @property
    def describe(self) -> str:
        return f"{self.file}:{self.line} [{self.operator}] {self.original} -> {self.mutated}"


def generate(
    source: str, *, filename: str, lines: set[int] | None = None
) -> list[MutationCandidate]:
    """Every mutation this module can make to ``source``.

    ``lines`` restricts generation to the lines a patch touched, which is the
    default scope: falsification is evidence about a change, not a codebase audit.
    Passing ``None`` mutates the whole file.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # A file that does not parse cannot be mutated. This is not an error worth
        # failing a run over - it is reported by the caller as a skipped file.
        return []

    docstrings = _docstring_nodes(tree)
    candidates: list[MutationCandidate] = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", None)
        if line is None or (lines is not None and line not in lines):
            continue
        if id(node) in docstrings:
            # Blanking a docstring is not an injected fault. It survives every suite
            # ever written, and reporting that as a test weakness is how a report
            # earns the reputation of being noise.
            continue
        candidates.extend(_mutations_for(node, source, filename))

    # Stable order: by line, then operator, so a run is reproducible and two runs of
    # the same patch generate the same mutants in the same order.
    return sorted(candidates, key=lambda c: (c.line, c.operator, c.mutated))


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """Ids of the string constants that are docstrings rather than data."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            found.add(id(first.value))
    return found


def _mutations_for(node: ast.AST, source: str, filename: str) -> list[MutationCandidate]:
    if isinstance(node, ast.BinOp):
        return _arithmetic(node, source, filename)
    if isinstance(node, ast.Compare):
        return _comparison(node, source, filename)
    if isinstance(node, ast.BoolOp):
        return _boolean(node, source, filename)
    if isinstance(node, ast.If):
        return _conditional(node, source, filename)
    if isinstance(node, ast.Return):
        return _return_value(node, source, filename)
    if isinstance(node, ast.Constant):
        return _constant(node, source, filename)
    if isinstance(node, ast.Raise):
        return _exception(node, source, filename)
    return []


# --------------------------------------------------------------------------- operators


def _arithmetic(node: ast.BinOp, source: str, filename: str) -> list[MutationCandidate]:
    replacement = _ARITHMETIC_SWAPS.get(type(node.op))
    if replacement is None:
        return []
    # String concatenation is not arithmetic: "a" - "b" is a guaranteed TypeError,
    # which is an invalid mutant rather than a realistic fault.
    if isinstance(node.op, ast.Add) and _looks_textual(node):
        return []
    return _swap_operator(
        node.op, replacement, source, filename, ARITHMETIC, node.lineno
    )


def _comparison(node: ast.Compare, source: str, filename: str) -> list[MutationCandidate]:
    out: list[MutationCandidate] = []
    for op in node.ops:
        replacement = _COMPARISON_SWAPS.get(type(op))
        if replacement is None:
            continue
        operator = BOUNDARY if type(op) in {ast.Lt, ast.LtE, ast.Gt, ast.GtE} else COMPARISON
        out.extend(_swap_operator(op, replacement, source, filename, operator, node.lineno))
    return out


def _boolean(node: ast.BoolOp, source: str, filename: str) -> list[MutationCandidate]:
    replacement = ast.Or if isinstance(node.op, ast.And) else ast.And
    return _swap_operator(node.op, replacement, source, filename, BOOLEAN, node.lineno)


def _conditional(node: ast.If, source: str, filename: str) -> list[MutationCandidate]:
    """Negate a condition: ``if x:`` becomes ``if not (x):``.

    Rewritten textually on the test expression's own span so that comments,
    formatting and the body are all preserved exactly.
    """
    span = _span(node.test, source)
    if span is None:
        return []
    start, end, text = span
    # Double negation reads badly and tests nothing new, so an already-negated
    # condition is un-negated instead.
    mutated_text = text[4:] if text.startswith("not ") else f"not ({text})"
    return [
        MutationCandidate(
            file=filename,
            line=node.test.lineno,
            operator=CONDITIONAL,
            original=text,
            mutated=mutated_text,
            source=source[:start] + mutated_text + source[end:],
            target=OPERATOR_TARGETS[CONDITIONAL],
        )
    ]


def _return_value(node: ast.Return, source: str, filename: str) -> list[MutationCandidate]:
    """Replace a returned expression with a degenerate value of a plausible shape."""
    if node.value is None:
        return []
    span = _span(node.value, source)
    if span is None:
        return []
    start, end, text = span

    replacement = _degenerate_return(node.value, text)
    if replacement is None or replacement == text:
        return []
    return [
        MutationCandidate(
            file=filename,
            line=node.lineno,
            operator=RETURN_VALUE,
            original=text,
            mutated=replacement,
            source=source[:start] + replacement + source[end:],
            target=OPERATOR_TARGETS[RETURN_VALUE],
        )
    ]


def _constant(node: ast.Constant, source: str, filename: str) -> list[MutationCandidate]:
    """Perturb a literal. Docstrings and type-ish constants are left alone."""
    value = node.value
    if isinstance(value, bool):
        replacement = repr(not value)
    elif isinstance(value, int):
        # 0 -> 1 and n -> n+1: an off-by-one is the realistic constant fault.
        replacement = repr(value + 1)
    elif isinstance(value, float):
        replacement = repr(value + 1.0)
    elif isinstance(value, str):
        if len(value) > 60 or "\n" in value:
            return []  # docstrings and messages: mutating them tests nothing useful
        replacement = repr("" if value else "devforge-mutant")
    else:
        return []

    span = _span(node, source)
    if span is None:
        return []
    start, end, text = span
    if text != repr(value) and not _literal_matches(text, value):
        # The span did not isolate a literal cleanly (f-strings, implicit
        # concatenation). Skipping is better than corrupting the file.
        return []
    return [
        MutationCandidate(
            file=filename,
            line=node.lineno,
            operator=CONSTANT,
            original=text,
            mutated=replacement,
            source=source[:start] + replacement + source[end:],
            target=OPERATOR_TARGETS[CONSTANT],
        )
    ]


def _exception(node: ast.Raise, source: str, filename: str) -> list[MutationCandidate]:
    """Remove a raise, replacing the error path with a silent success.

    The most consequential mutation in the set: if the suite does not notice that an
    error is no longer raised, nothing tests the error path at all.
    """
    span = _span(node, source)
    if span is None:
        return []
    start, end, text = span
    indent = _indent_at(source, start)
    replacement = f"pass  # devforge-mutant: raise removed\n{indent}"
    # Keep the trailing newline structure intact by replacing only the statement.
    return [
        MutationCandidate(
            file=filename,
            line=node.lineno,
            operator=EXCEPTION,
            original=text,
            mutated="pass",
            source=source[:start] + replacement.rstrip() + source[end:],
            target=OPERATOR_TARGETS[EXCEPTION],
        )
    ]


def branch_removal(
    source: str, *, filename: str, lines: set[int] | None = None
) -> list[MutationCandidate]:
    """Force a branch to always or never be taken.

    Kept separate from :func:`generate` because it is the coarsest operator in the
    set: it changes control flow wholesale rather than perturbing one expression, and
    a caller may reasonably want the cheaper operators only.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    out: list[MutationCandidate] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        if lines is not None and node.lineno not in lines:
            continue
        span = _span(node.test, source)
        if span is None:
            continue
        start, end, text = span
        for literal in ("True", "False"):
            if text == literal:
                continue
            out.append(
                MutationCandidate(
                    file=filename,
                    line=node.test.lineno,
                    operator=BRANCH,
                    original=text,
                    mutated=literal,
                    source=source[:start] + literal + source[end:],
                    target=OPERATOR_TARGETS[BRANCH],
                )
            )
    return out


# --------------------------------------------------------------------------- helpers


def _swap_operator(
    node: ast.AST,
    replacement: type,
    source: str,
    filename: str,
    operator: str,
    line: int,
) -> list[MutationCandidate]:
    """Rewrite one operator token in place, by text.

    Operator nodes carry no reliable column span, so the token is located within the
    line. A line containing the same token more than once is skipped: guessing which
    occurrence the AST meant would silently mutate the wrong one.
    """
    original_text = _OPERATOR_TEXT.get(type(node))
    replacement_text = _OPERATOR_TEXT.get(replacement)
    if not original_text or not replacement_text:
        return []

    lines = source.splitlines(keepends=True)
    if line - 1 >= len(lines):
        return []
    offset = sum(len(item) for item in lines[: line - 1])
    text = lines[line - 1]

    positions = _token_positions(text, original_text)
    if len(positions) != 1:
        return []
    column = positions[0]

    start = offset + column
    end = start + len(original_text)
    return [
        MutationCandidate(
            file=filename,
            line=line,
            operator=operator,
            original=original_text,
            mutated=replacement_text,
            source=source[:start] + replacement_text + source[end:],
            target=OPERATOR_TARGETS[operator],
            col=column,
        )
    ]


def _token_positions(text: str, token: str) -> list[int]:
    """Where ``token`` appears in ``text`` as an operator, ignoring strings.

    Crude but conservative: anything inside quotes or after a ``#`` is skipped, and
    a word-shaped token (``is``, ``in``, ``and``) must stand alone.
    """
    positions: list[int] = []
    quote: str | None = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "\"'":
            quote = char
            index += 1
            continue
        if char == "#":
            break
        if text.startswith(token, index):
            if token.isalpha():
                before = text[index - 1] if index else " "
                after_index = index + len(token)
                after = text[after_index] if after_index < len(text) else " "
                if before.isalnum() or before == "_" or after.isalnum() or after == "_":
                    index += 1
                    continue
            else:
                # "==" must not match inside ">=", and "+" must not match "+=".
                after_index = index + len(token)
                after = text[after_index] if after_index < len(text) else " "
                before = text[index - 1] if index else " "
                if after == "=" or before in "=<>!+-*/%":
                    index += 1
                    continue
            positions.append(index)
            index += len(token)
            continue
        index += 1
    return positions


def _span(node: ast.AST, source: str) -> tuple[int, int, str] | None:
    """Absolute character span of a node, or ``None`` when it cannot be located."""
    lineno = getattr(node, "lineno", None)
    end_lineno = getattr(node, "end_lineno", None)
    col = getattr(node, "col_offset", None)
    end_col = getattr(node, "end_col_offset", None)
    if None in (lineno, end_lineno, col, end_col):
        return None

    lines = source.splitlines(keepends=True)
    if end_lineno > len(lines):
        return None
    start = sum(len(item) for item in lines[: lineno - 1]) + col
    end = sum(len(item) for item in lines[: end_lineno - 1]) + end_col
    if start >= end or end > len(source):
        return None
    return start, end, source[start:end]


def _indent_at(source: str, position: int) -> str:
    line_start = source.rfind("\n", 0, position) + 1
    return source[line_start:position]


def _looks_textual(node: ast.BinOp) -> bool:
    """Whether a ``+`` is plausibly string or list concatenation."""
    for side in (node.left, node.right):
        if isinstance(side, ast.Constant) and isinstance(side.value, str):
            return True
        if isinstance(side, ast.JoinedStr | ast.List | ast.Tuple):
            return True
    return False


def _degenerate_return(node: ast.AST, text: str) -> str | None:
    """A plausible wrong value of the same shape as what is returned."""
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, bool):
            return repr(not value)
        if isinstance(value, int | float):
            return "0"
        if isinstance(value, str):
            return '""'
        if value is None:
            return None
        return None
    if isinstance(node, ast.List):
        return "[]"
    if isinstance(node, ast.Dict):
        return "{}"
    if isinstance(node, ast.Tuple):
        return "()"
    if isinstance(node, ast.Compare | ast.BoolOp):
        return f"not ({text})"
    # An arbitrary expression: None is the classic "forgot to return" fault.
    return "None"


def _literal_matches(text: str, value: object) -> bool:
    """Whether a source span is a plain literal for ``value``."""
    stripped = text.strip()
    if isinstance(value, str):
        return len(stripped) >= 2 and stripped[0] in "\"'" and stripped[-1] in "\"'"
    return stripped.replace("_", "") == str(value)
