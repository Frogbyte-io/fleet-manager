// A deliberately small SPDX license-expression evaluator.
//
// Package metadata rarely holds a bare identifier: "(MIT OR Apache-2.0)" is the
// npm norm and "Apache-2.0 WITH LLVM-exception" is the Rust norm. Answering
// "does this satisfy the allow list" therefore needs the OR/AND/WITH grammar,
// not a string comparison. cargo-deny does this properly for Cargo; this covers
// the same ground for lockfiles cargo-deny never sees.
//
// SPDX identifiers are case-insensitive, so matching is too.

function tokenize(expression) {
  return expression
    .replace(/([()])/g, ' $1 ')
    .split(/\s+/)
    .filter(Boolean);
}

/**
 * @param {string} expression an SPDX license expression
 * @param {Iterable<string>} allowed allowed identifiers
 * @returns {boolean} whether the expression can be satisfied by the allowed set
 */
export function satisfies(expression, allowed) {
  const permitted = new Set([...allowed].map((id) => id.toLowerCase()));
  const tokens = tokenize(expression);
  let position = 0;

  const peek = () => tokens[position];
  const next = () => tokens[position++];

  function parseFactor() {
    const token = next();
    if (token === undefined) throw new Error(`unexpected end of license expression ${JSON.stringify(expression)}`);
    if (token === '(') {
      const value = parseExpression();
      if (next() !== ')') throw new Error(`unbalanced parentheses in license expression ${JSON.stringify(expression)}`);
      return value;
    }
    if (token === ')' || /^(AND|OR|WITH)$/i.test(token)) {
      throw new Error(`unexpected ${JSON.stringify(token)} in license expression ${JSON.stringify(expression)}`);
    }
    // "Apache-2.0 WITH LLVM-exception" is one identifier, not two.
    let identifier = token;
    if (peek() !== undefined && /^WITH$/i.test(peek())) {
      next();
      const exception = next();
      if (exception === undefined) throw new Error(`dangling WITH in license expression ${JSON.stringify(expression)}`);
      identifier = `${identifier} WITH ${exception}`;
    }
    return permitted.has(identifier.toLowerCase());
  }

  function parseTerm() {
    let value = parseFactor();
    while (peek() !== undefined && /^AND$/i.test(peek())) {
      next();
      // Both halves of an AND must be allowed: the obligations combine.
      value = parseFactor() && value;
    }
    return value;
  }

  function parseExpression() {
    let value = parseTerm();
    while (peek() !== undefined && /^OR$/i.test(peek())) {
      next();
      // Either half is enough: we choose the allowed one.
      value = parseTerm() || value;
    }
    return value;
  }

  const result = parseExpression();
  if (position !== tokens.length) {
    throw new Error(`trailing tokens in license expression ${JSON.stringify(expression)}`);
  }
  return result;
}
