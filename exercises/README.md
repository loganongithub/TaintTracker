# Phase 1 exercises

Put each solution in this folder (`ex1.py`, `ex2.py`, `ex3.py`). These are scratch work and are not imported by the tool.

## Exercise 1: read a tree

- Write a six-line Flask handler that reads `request.args.get("url")` and passes it to `requests.get`.
- Draw the tree for the `request.args.get("url")` line on paper first.
- Print the real tree with `ast.parse` and `ast.dump(..., indent=2)` and compare.
- Which node types appear, and how are they nested? Why is the outermost node what it is?

## Exercise 2: list every call

- Print the line number and full dotted name of every function call in a file, such as `12 requests.get` or `15 open`.
- Do it once with `ast.walk` and once with an `ast.NodeVisitor` subclass.
- Decide what to print for something like `get_client().fetch(x)`.

## Exercise 3: who feeds whom

- For every assignment, print the names written and the names read: `x = a + f(b)` gives `x <- {a, f, b}`.
- Then handle `a, b = c, d`, then `x += y`, then an f-string on the right-hand side.
- Take this one slowly. It is the core of taint propagation.
