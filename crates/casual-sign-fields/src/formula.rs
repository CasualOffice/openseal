//! The formula language (docs/30 §6, ADR-022): small, total, decimal.
//!
//! ```text
//! expr    := sum (cmp sum)?            cmp := = | <> | < | <= | > | >=
//! sum     := product (('+' | '-') product)*
//! product := unary (('*' | '/') unary)*
//! unary   := ('-' | '+') unary | primary
//! primary := number | label | '[' any label ']' | name '(' expr (',' expr)* ')' | '(' expr ')'
//! ```
//!
//! Functions: `IF(c, a, b)`, `SUM`, `MIN`, `MAX` (one or more arguments), `ROUND(x)` or
//! `ROUND(x, places)`, `ABS(x)`, `DAYS(end, start)` (two date-field labels; whole days).
//! Names are case-insensitive. Comparisons give 1 or 0; `IF` takes any non-zero as true
//! and evaluates only the branch it takes.
//!
//! **Bounds** (docs/21): 1,024 characters, checked before anything is read; 32 levels of
//! nesting (brackets, calls, signs); 100 label references. Operator chains are kept
//! flat (`a+b+c` is one node with three terms), so no tree is deeper than its nesting
//! and nothing recurses past the depth bound. Evaluation is total: division by zero,
//! overflow and non-numbers are [`ErrorValue`]s, never panics.

use casual_sign_model::limits::{
    MAX_FORMULA_CHARS, MAX_FORMULA_DEPTH, MAX_FORMULA_REFERENCES, MAX_PRECISION,
};
use rust_decimal::{Decimal, RoundingStrategy};
use unicode_normalization::char::is_combining_mark;

use crate::error::FormulaError;
use crate::label_key;

/// A runtime error value: what a formula shows instead of a number (docs/30 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ErrorValue {
    /// Division by zero.
    DivisionByZero,
    /// A result too large for a decimal (about 7.9 × 10²⁸).
    Overflow,
    /// A referenced value is not a number.
    NotANumber,
    /// A `DAYS` argument is not a date in its field's format.
    NotADate,
    /// `ROUND`'s places are not a whole number from 0 to 15.
    BadPlaces,
}

impl ErrorValue {
    /// A stable name for the value, for display and the API.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::DivisionByZero => "division_by_zero",
            Self::Overflow => "overflow",
            Self::NotANumber => "not_a_number",
            Self::NotADate => "not_a_date",
            Self::BadPlaces => "bad_places",
        }
    }
}

/// What a formula reads from the envelope: numbers and dates by data label.
pub trait Env {
    /// The number a label holds; an empty or hidden field is 0.
    fn number(&self, label: &str) -> Result<Decimal, ErrorValue>;
    /// The date a label holds, as days since 1970-01-01.
    fn date(&self, label: &str) -> Result<i64, ErrorValue>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Func {
    If,
    Sum,
    Min,
    Max,
    Round,
    Abs,
    Days,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Number(Decimal),
    /// Index into [`Expression::references`].
    Ref(usize),
    Neg(Box<Node>),
    /// `first op term op term …`, all one precedence level, left to right.
    Chain(Box<Node>, Vec<(Op, Node)>),
    Compare(Cmp, Box<Node>, Box<Node>),
    Call(Func, Vec<Node>),
}

/// A parsed formula: its tree and the labels it reads, NFC-normalized, in order of
/// appearance (repeats kept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expression {
    root: Node,
    references: Vec<String>,
}

impl Expression {
    /// The labels this formula reads, NFC-normalized, in order of appearance.
    #[must_use]
    pub fn references(&self) -> &[String] {
        &self.references
    }

    /// Evaluates against `env`. Total: every outcome is a number or an [`ErrorValue`].
    pub fn evaluate(&self, env: &dyn Env) -> Result<Decimal, ErrorValue> {
        eval(&self.root, &self.references, env)
    }
}

/// Parses a formula, refusing it over its bounds before reading more than it must.
pub fn parse_formula(text: &str) -> Result<Expression, FormulaError> {
    // The length bound is first: a 100,000-character formula is refused after counting
    // 1,025 characters, without being lexed.
    if text.chars().nth(MAX_FORMULA_CHARS).is_some() {
        return Err(FormulaError::TooLong {
            limit: MAX_FORMULA_CHARS,
        });
    }
    let tokens = lex(text)?;
    let mut parser = Parser {
        tokens: &tokens,
        pos: 0,
        depth: 0,
        references: Vec::new(),
        end: text.len(),
    };
    let root = parser.expr()?;
    if let Some(t) = parser.peek() {
        return Err(FormulaError::Syntax { offset: t.offset });
    }
    Ok(Expression {
        root,
        references: parser.references,
    })
}

/// Formats a result at `precision` places, rounding half away from zero: `2.5` at 0
/// places is `3`, `-2.5` is `-3`. The text is what the signer sees and what a client
/// must send back.
#[must_use]
pub fn format_result(value: Decimal, precision: u8) -> String {
    let places = u32::from(precision.min(MAX_PRECISION));
    let rounded = value.round_dp_with_strategy(places, RoundingStrategy::MidpointAwayFromZero);
    let rounded = if rounded.is_zero() {
        Decimal::ZERO
    } else {
        rounded
    };
    // Not `format!("{rounded:.places$}")`: rust_decimal formats a precision into a
    // fixed-size buffer that a 29-digit value overflows, and that is a panic. Its plain
    // `Display` has room for every value; the zeros are padded here.
    let mut text = rounded.to_string();
    let places = usize::from(precision.min(MAX_PRECISION));
    let have = text.split_once('.').map_or(0, |(_, frac)| frac.len());
    if places > 0 && have == 0 {
        text.push('.');
    }
    for _ in have..places {
        text.push('0');
    }
    text
}

// ---- lexer -------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Number(Decimal),
    Name(String),
    Label(String),
    Op(Op),
    Cmp(Cmp),
    Open,
    Close,
    Comma,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    tok: Tok,
    offset: usize,
}

fn lex(text: &str) -> Result<Vec<Token>, FormulaError> {
    let mut tokens = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((offset, c)) = chars.next() {
        let tok = match c {
            c if c.is_whitespace() => continue,
            '+' => Tok::Op(Op::Add),
            '-' => Tok::Op(Op::Sub),
            '*' => Tok::Op(Op::Mul),
            '/' => Tok::Op(Op::Div),
            '(' => Tok::Open,
            ')' => Tok::Close,
            ',' => Tok::Comma,
            '=' => Tok::Cmp(Cmp::Eq),
            '<' => match chars.peek() {
                Some((_, '=')) => {
                    chars.next();
                    Tok::Cmp(Cmp::Le)
                }
                Some((_, '>')) => {
                    chars.next();
                    Tok::Cmp(Cmp::Ne)
                }
                _ => Tok::Cmp(Cmp::Lt),
            },
            '>' => match chars.peek() {
                Some((_, '=')) => {
                    chars.next();
                    Tok::Cmp(Cmp::Ge)
                }
                _ => Tok::Cmp(Cmp::Gt),
            },
            '0'..='9' => {
                let mut end = offset.saturating_add(1);
                let mut seen_dot = false;
                while let Some(&(i, d)) = chars.peek() {
                    if d.is_ascii_digit() || (d == '.' && !seen_dot) {
                        seen_dot |= d == '.';
                        end = i.saturating_add(1);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let literal = text
                    .get(offset..end)
                    .ok_or(FormulaError::Syntax { offset })?;
                if literal.ends_with('.') {
                    return Err(FormulaError::Syntax { offset });
                }
                let value = Decimal::from_str_exact(literal)
                    .map_err(|_| FormulaError::NumberOutOfRange { offset })?;
                Tok::Number(value)
            }
            '[' => {
                let mut label = String::new();
                loop {
                    match chars.next() {
                        Some((_, ']')) => break,
                        Some((_, c)) if !c.is_control() && c != '[' => label.push(c),
                        _ => return Err(FormulaError::Syntax { offset }),
                    }
                }
                if label.is_empty() {
                    return Err(FormulaError::Syntax { offset });
                }
                Tok::Label(label)
            }
            c if c.is_alphabetic() || c == '_' => {
                let mut name = String::from(c);
                while let Some(&(_, d)) = chars.peek() {
                    if d.is_alphanumeric() || d == '_' || d == '.' || is_combining_mark(d) {
                        name.push(d);
                        chars.next();
                    } else {
                        break;
                    }
                }
                Tok::Name(name)
            }
            _ => return Err(FormulaError::Syntax { offset }),
        };
        tokens.push(Token { tok, offset });
    }
    Ok(tokens)
}

// ---- parser ------------------------------------------------------------------------

struct Parser<'t> {
    tokens: &'t [Token],
    pos: usize,
    depth: usize,
    references: Vec<String>,
    end: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<&Token> {
        let t = self.tokens.get(self.pos);
        if t.is_some() {
            self.pos = self.pos.saturating_add(1);
        }
        t
    }

    fn here(&self) -> usize {
        self.peek().map_or(self.end, |t| t.offset)
    }

    /// Enters one nesting level; every recursive path passes through here.
    fn nest<T>(
        &mut self,
        inner: impl FnOnce(&mut Self) -> Result<T, FormulaError>,
    ) -> Result<T, FormulaError> {
        if self.depth >= MAX_FORMULA_DEPTH {
            return Err(FormulaError::TooDeep {
                limit: MAX_FORMULA_DEPTH,
            });
        }
        self.depth = self.depth.saturating_add(1);
        let result = inner(self);
        self.depth = self.depth.saturating_sub(1);
        result
    }

    fn expr(&mut self) -> Result<Node, FormulaError> {
        let left = self.sum()?;
        let Some(Tok::Cmp(cmp)) = self.peek().map(|t| &t.tok) else {
            return Ok(left);
        };
        let cmp = *cmp;
        self.next();
        let right = self.sum()?;
        if let Some(Token {
            tok: Tok::Cmp(_),
            offset,
        }) = self.peek()
        {
            // `a < b < c` reads as a chain in mathematics and as a comparison of a
            // comparison here; refused rather than guessed.
            return Err(FormulaError::Syntax { offset: *offset });
        }
        Ok(Node::Compare(cmp, Box::new(left), Box::new(right)))
    }

    fn sum(&mut self) -> Result<Node, FormulaError> {
        self.chain(&[Op::Add, Op::Sub], Self::product)
    }

    fn product(&mut self) -> Result<Node, FormulaError> {
        self.chain(&[Op::Mul, Op::Div], Self::unary)
    }

    fn chain(
        &mut self,
        ops: &[Op],
        term: fn(&mut Self) -> Result<Node, FormulaError>,
    ) -> Result<Node, FormulaError> {
        let first = term(self)?;
        let mut rest = Vec::new();
        while let Some(Tok::Op(op)) = self.peek().map(|t| &t.tok) {
            let op = *op;
            if !ops.contains(&op) {
                break;
            }
            self.next();
            rest.push((op, term(self)?));
        }
        Ok(if rest.is_empty() {
            first
        } else {
            Node::Chain(Box::new(first), rest)
        })
    }

    fn unary(&mut self) -> Result<Node, FormulaError> {
        match self.peek().map(|t| &t.tok) {
            Some(Tok::Op(Op::Sub)) => {
                self.next();
                self.nest(|p| p.unary().map(|n| Node::Neg(Box::new(n))))
            }
            Some(Tok::Op(Op::Add)) => {
                self.next();
                self.nest(Self::unary)
            }
            _ => self.primary(),
        }
    }

    fn reference(&mut self, label: &str) -> Result<Node, FormulaError> {
        if self.references.len() >= MAX_FORMULA_REFERENCES {
            return Err(FormulaError::TooManyReferences {
                limit: MAX_FORMULA_REFERENCES,
            });
        }
        self.references.push(label_key(label));
        Ok(Node::Ref(self.references.len().saturating_sub(1)))
    }

    fn primary(&mut self) -> Result<Node, FormulaError> {
        let offset = self.here();
        let Some(token) = self.next() else {
            return Err(FormulaError::Syntax { offset });
        };
        match token.tok.clone() {
            Tok::Number(n) => Ok(Node::Number(n)),
            Tok::Label(label) => self.reference(&label),
            Tok::Open => {
                let inner = self.nest(Self::expr)?;
                self.expect_close()?;
                Ok(inner)
            }
            Tok::Name(name) => {
                if matches!(self.peek().map(|t| &t.tok), Some(Tok::Open)) {
                    self.next();
                    self.call(&name, offset)
                } else {
                    self.reference(&name)
                }
            }
            Tok::Op(_) | Tok::Cmp(_) | Tok::Close | Tok::Comma => {
                Err(FormulaError::Syntax { offset })
            }
        }
    }

    fn expect_close(&mut self) -> Result<(), FormulaError> {
        let offset = self.here();
        match self.next().map(|t| &t.tok) {
            Some(Tok::Close) => Ok(()),
            _ => Err(FormulaError::Syntax { offset }),
        }
    }

    fn call(&mut self, name: &str, offset: usize) -> Result<Node, FormulaError> {
        let func = match name.to_ascii_uppercase().as_str() {
            "IF" => Func::If,
            "SUM" => Func::Sum,
            "MIN" => Func::Min,
            "MAX" => Func::Max,
            "ROUND" => Func::Round,
            "ABS" => Func::Abs,
            "DAYS" => Func::Days,
            _ => return Err(FormulaError::UnknownFunction { offset }),
        };
        let args = self.nest(|p| {
            let mut args = vec![p.expr()?];
            while matches!(p.peek().map(|t| &t.tok), Some(Tok::Comma)) {
                p.next();
                args.push(p.expr()?);
            }
            p.expect_close()?;
            Ok(args)
        })?;
        let arity_ok = match func {
            Func::If => args.len() == 3,
            Func::Sum | Func::Min | Func::Max => !args.is_empty(),
            Func::Round => (1..=2).contains(&args.len()),
            Func::Abs => args.len() == 1,
            Func::Days => args.len() == 2 && args.iter().all(|a| matches!(a, Node::Ref(_))),
        };
        if !arity_ok {
            return Err(FormulaError::Arguments { offset });
        }
        Ok(Node::Call(func, args))
    }
}

// ---- evaluator ---------------------------------------------------------------------

fn eval(node: &Node, refs: &[String], env: &dyn Env) -> Result<Decimal, ErrorValue> {
    match node {
        Node::Number(n) => Ok(*n),
        Node::Ref(i) => env.number(refs.get(*i).ok_or(ErrorValue::NotANumber)?),
        // Negating a decimal cannot overflow: its range is symmetric.
        Node::Neg(inner) => Ok(core::ops::Neg::neg(eval(inner, refs, env)?)),
        Node::Chain(first, rest) => {
            let mut acc = eval(first, refs, env)?;
            for (op, term) in rest {
                let rhs = eval(term, refs, env)?;
                acc = arith(*op, acc, rhs)?;
            }
            Ok(acc)
        }
        Node::Compare(cmp, left, right) => {
            let (l, r) = (eval(left, refs, env)?, eval(right, refs, env)?);
            let truth = match cmp {
                Cmp::Eq => l == r,
                Cmp::Ne => l != r,
                Cmp::Lt => l < r,
                Cmp::Le => l <= r,
                Cmp::Gt => l > r,
                Cmp::Ge => l >= r,
            };
            Ok(if truth { Decimal::ONE } else { Decimal::ZERO })
        }
        Node::Call(func, args) => call(*func, args, refs, env),
    }
}

fn arith(op: Op, l: Decimal, r: Decimal) -> Result<Decimal, ErrorValue> {
    match op {
        Op::Add => l.checked_add(r),
        Op::Sub => l.checked_sub(r),
        Op::Mul => l.checked_mul(r),
        Op::Div if r.is_zero() => return Err(ErrorValue::DivisionByZero),
        Op::Div => l.checked_div(r),
    }
    .ok_or(ErrorValue::Overflow)
}

fn call(func: Func, args: &[Node], refs: &[String], env: &dyn Env) -> Result<Decimal, ErrorValue> {
    let arg = |i: usize| -> Result<Decimal, ErrorValue> {
        args.get(i)
            .map_or(Err(ErrorValue::NotANumber), |a| eval(a, refs, env))
    };
    match func {
        Func::If => {
            if arg(0)?.is_zero() {
                arg(2)
            } else {
                arg(1)
            }
        }
        Func::Sum => args.iter().try_fold(Decimal::ZERO, |acc, a| {
            arith(Op::Add, acc, eval(a, refs, env)?)
        }),
        Func::Min | Func::Max => {
            let mut best = arg(0)?;
            for a in args.iter().skip(1) {
                let v = eval(a, refs, env)?;
                if (func == Func::Min && v < best) || (func == Func::Max && v > best) {
                    best = v;
                }
            }
            Ok(best)
        }
        Func::Round => {
            let value = arg(0)?;
            let places = if args.len() > 1 {
                arg(1)?
            } else {
                Decimal::ZERO
            };
            if !places.fract().is_zero()
                || places.is_sign_negative() && !places.is_zero()
                || places > Decimal::from(MAX_PRECISION)
            {
                return Err(ErrorValue::BadPlaces);
            }
            let places =
                u32::try_from(places.trunc().mantissa()).map_err(|_| ErrorValue::BadPlaces)?;
            Ok(value.round_dp_with_strategy(places, RoundingStrategy::MidpointAwayFromZero))
        }
        Func::Abs => Ok(arg(0)?.abs()),
        Func::Days => {
            let date = |i: usize| match args.get(i) {
                Some(Node::Ref(r)) => env.date(refs.get(*r).ok_or(ErrorValue::NotADate)?),
                _ => Err(ErrorValue::NotADate),
            };
            let (end, start) = (date(0)?, date(1)?);
            end.checked_sub(start)
                .map(Decimal::from)
                .ok_or(ErrorValue::Overflow)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Vars(
        BTreeMap<String, Result<Decimal, ErrorValue>>,
        BTreeMap<String, i64>,
    );

    impl Env for Vars {
        fn number(&self, label: &str) -> Result<Decimal, ErrorValue> {
            self.0.get(label).copied().unwrap_or(Ok(Decimal::ZERO))
        }
        fn date(&self, label: &str) -> Result<i64, ErrorValue> {
            self.1.get(label).copied().ok_or(ErrorValue::NotADate)
        }
    }

    fn vars() -> Vars {
        let mut n = BTreeMap::new();
        for (k, v) in [
            ("a", "2"),
            ("b", "3"),
            ("price", "19.99"),
            ("qty", "3"),
            ("zero", "0"),
            ("big", "79228162514264337593543950335"),
        ] {
            n.insert(k.to_owned(), Ok(v.parse::<Decimal>().unwrap_or_default()));
        }
        n.insert("Prix unitaire".to_owned(), Ok(Decimal::from(10)));
        n.insert(label_key("café"), Ok(Decimal::from(7)));
        n.insert("bad".to_owned(), Err(ErrorValue::NotANumber));
        let mut d = BTreeMap::new();
        d.insert("start".to_owned(), 0);
        d.insert("end".to_owned(), 31);
        Vars(n, d)
    }

    fn run(text: &str) -> Result<Result<String, ErrorValue>, FormulaError> {
        let e = parse_formula(text)?;
        Ok(e.evaluate(&vars()).map(|d| d.normalize().to_string()))
    }

    fn ok(text: &str) -> String {
        match run(text) {
            Ok(Ok(s)) => s,
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn arithmetic_is_decimal_and_follows_precedence() {
        assert_eq!(ok("1 + 2 * 3"), "7");
        assert_eq!(ok("(1 + 2) * 3"), "9");
        assert_eq!(ok("0.1 + 0.2"), "0.3");
        assert_eq!(ok("10 - 4 - 3"), "3");
        assert_eq!(ok("100 / 10 / 5"), "2");
        assert_eq!(ok("-a + +b"), "1");
        assert_eq!(ok("--2"), "2");
        assert_eq!(ok("price * qty"), "59.97");
        // Decimal, not rational: a third has 28 places, and the field's precision rounds it.
        assert_eq!(ok("1/3*3"), "0.9999999999999999999999999999");
        assert_eq!(
            format_result(
                parse_formula("1/3*3")
                    .map(|e| e.evaluate(&vars()))
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default(),
                2
            ),
            "1.00"
        );
    }

    #[test]
    fn comparisons_give_one_or_zero() {
        assert_eq!(ok("a < b"), "1");
        assert_eq!(ok("a >= b"), "0");
        assert_eq!(ok("a <> b"), "1");
        assert_eq!(ok("2.0 = 2"), "1");
        assert_eq!(ok("a <= 2"), "1");
        assert_eq!(ok("a > 2"), "0");
        assert!(matches!(run("1 < 2 < 3"), Err(FormulaError::Syntax { .. })));
    }

    #[test]
    fn functions_compute() {
        assert_eq!(ok("IF(a > 1, 10, 20)"), "10");
        assert_eq!(ok("if(a > 5, 10, 20)"), "20");
        assert_eq!(
            ok("IF(zero, 1 / zero, 5)"),
            "5",
            "IF evaluates only the branch it takes"
        );
        assert_eq!(ok("SUM(1, 2, a, b)"), "8");
        assert_eq!(ok("SUM(a)"), "2");
        assert_eq!(ok("MIN(3, a, b)"), "2");
        assert_eq!(ok("MAX(3, a, -b)"), "3");
        assert_eq!(ok("ROUND(2.5)"), "3");
        assert_eq!(ok("ROUND(-2.5)"), "-3");
        assert_eq!(ok("ROUND(1.2345, 2)"), "1.23");
        assert_eq!(ok("ROUND(1.235, 2)"), "1.24");
        assert_eq!(ok("ABS(-4.5)"), "4.5");
        assert_eq!(ok("DAYS(end, start)"), "31");
        assert_eq!(ok("DAYS(start, end)"), "-31");
    }

    #[test]
    fn errors_are_values_not_panics() {
        assert_eq!(run("1 / 0"), Ok(Err(ErrorValue::DivisionByZero)));
        assert_eq!(run("a / zero"), Ok(Err(ErrorValue::DivisionByZero)));
        assert_eq!(run("1 / (a - 2)"), Ok(Err(ErrorValue::DivisionByZero)));
        assert_eq!(run("big * big"), Ok(Err(ErrorValue::Overflow)));
        assert_eq!(run("big + 1"), Ok(Err(ErrorValue::Overflow)));
        assert_eq!(run("-big - big"), Ok(Err(ErrorValue::Overflow)));
        assert_eq!(
            run("big / 0.0000000000000000000000000001"),
            Ok(Err(ErrorValue::Overflow))
        );
        assert_eq!(run("bad + 1"), Ok(Err(ErrorValue::NotANumber)));
        assert_eq!(run("ROUND(1, 16)"), Ok(Err(ErrorValue::BadPlaces)));
        assert_eq!(run("ROUND(1, -1)"), Ok(Err(ErrorValue::BadPlaces)));
        assert_eq!(run("ROUND(1, 1.5)"), Ok(Err(ErrorValue::BadPlaces)));
        assert_eq!(run("DAYS(end, a)"), Ok(Err(ErrorValue::NotADate)));
        assert_eq!(run("SUM(big, big)"), Ok(Err(ErrorValue::Overflow)));
    }

    #[test]
    fn labels_may_be_unicode_bare_or_bracketed() {
        assert_eq!(ok("[Prix unitaire] * 2"), "20");
        // "café" composed and decomposed are one label after NFC.
        assert_eq!(ok("cafe\u{301} + 0"), "7");
        assert_eq!(ok("[café]"), "7");
        assert_eq!(
            parse_formula("[If] + Sum.total").map(|e| e.references().to_vec()),
            Ok(vec!["If".to_owned(), "Sum.total".to_owned()])
        );
        assert!(matches!(
            parse_formula("[]"),
            Err(FormulaError::Syntax { .. })
        ));
        assert!(matches!(
            parse_formula("[a"),
            Err(FormulaError::Syntax { .. })
        ));
        assert!(matches!(
            parse_formula("[a[b]"),
            Err(FormulaError::Syntax { .. })
        ));
    }

    #[test]
    fn syntax_errors_carry_offsets() {
        assert_eq!(
            parse_formula("1 +"),
            Err(FormulaError::Syntax { offset: 3 })
        );
        assert_eq!(parse_formula("(1"), Err(FormulaError::Syntax { offset: 2 }));
        assert_eq!(
            parse_formula("1 2"),
            Err(FormulaError::Syntax { offset: 2 })
        );
        assert_eq!(parse_formula(""), Err(FormulaError::Syntax { offset: 0 }));
        assert_eq!(
            parse_formula("1 ; 2"),
            Err(FormulaError::Syntax { offset: 2 })
        );
        assert_eq!(parse_formula("1."), Err(FormulaError::Syntax { offset: 0 }));
        assert_eq!(
            parse_formula("POW(2, 3)"),
            Err(FormulaError::UnknownFunction { offset: 0 })
        );
        assert_eq!(
            parse_formula("IF(1, 2)"),
            Err(FormulaError::Arguments { offset: 0 })
        );
        assert_eq!(
            parse_formula("ABS(1, 2)"),
            Err(FormulaError::Arguments { offset: 0 })
        );
        assert_eq!(
            parse_formula("DAYS(1, 2)"),
            Err(FormulaError::Arguments { offset: 0 })
        );
        assert_eq!(
            parse_formula("SUM()"),
            Err(FormulaError::Syntax { offset: 4 })
        );
        assert_eq!(parse_formula("NaN"), parse_formula("[NaN]"));
        assert_eq!(
            parse_formula("1e5"),
            Err(FormulaError::Syntax { offset: 1 })
        );
    }

    #[test]
    fn number_literals_over_decimal_range_are_refused() {
        assert!(parse_formula("79228162514264337593543950335").is_ok());
        assert_eq!(
            parse_formula("79228162514264337593543950336"),
            Err(FormulaError::NumberOutOfRange { offset: 0 })
        );
        assert_eq!(
            parse_formula(&"9".repeat(500)),
            Err(FormulaError::NumberOutOfRange { offset: 0 })
        );
    }

    #[test]
    fn length_bound_refuses_before_parsing() {
        assert!(parse_formula(&format!("1{}", "+1".repeat(511))).is_ok());
        let over = format!("1{}", "+1".repeat(512));
        assert_eq!(
            parse_formula(&over),
            Err(FormulaError::TooLong { limit: 1_024 })
        );
        // A syntax error at offset 0 would be found first if the text were lexed.
        let huge = format!(";{}", "1".repeat(100_000));
        assert_eq!(
            parse_formula(&huge),
            Err(FormulaError::TooLong { limit: 1_024 })
        );
    }

    #[test]
    fn depth_bound_counts_brackets_calls_and_signs() {
        let nested = |n: usize| format!("{}1{}", "(".repeat(n), ")".repeat(n));
        assert!(parse_formula(&nested(32)).is_ok());
        assert_eq!(
            parse_formula(&nested(33)),
            Err(FormulaError::TooDeep { limit: 32 })
        );
        assert_eq!(
            parse_formula(&nested(500)),
            Err(FormulaError::TooDeep { limit: 32 })
        );
        let calls = |n: usize| format!("{}1{}", "ABS(".repeat(n), ")".repeat(n));
        assert!(parse_formula(&calls(32)).is_ok());
        assert_eq!(
            parse_formula(&calls(33)),
            Err(FormulaError::TooDeep { limit: 32 })
        );
        assert!(parse_formula(&format!("{}1", "-".repeat(32))).is_ok());
        assert_eq!(
            parse_formula(&format!("{}1", "-".repeat(33))),
            Err(FormulaError::TooDeep { limit: 32 })
        );
    }

    #[test]
    fn reference_bound_counts_every_occurrence() {
        let refs = |n: usize| vec!["a"; n].join("+");
        assert_eq!(
            parse_formula(&refs(100)).map(|e| e.references().len()),
            Ok(100)
        );
        assert_eq!(
            parse_formula(&refs(101)),
            Err(FormulaError::TooManyReferences { limit: 100 })
        );
    }

    #[test]
    fn long_chains_stay_flat() {
        // 512 terms: within the length bound, and evaluated without deep recursion.
        assert_eq!(ok(&format!("1{}", "+1".repeat(511))), "512");
        assert_eq!(ok(&format!("1{}", "*1".repeat(511))), "1");
    }

    #[test]
    fn results_format_at_their_precision() {
        let d = |s: &str| s.parse::<Decimal>().unwrap_or_default();
        assert_eq!(format_result(d("2.5"), 0), "3");
        assert_eq!(format_result(d("-2.5"), 0), "-3");
        assert_eq!(format_result(d("1.005"), 2), "1.01");
        assert_eq!(format_result(d("7"), 2), "7.00");
        assert_eq!(format_result(d("-0.001"), 2), "0.00");
        assert_eq!(format_result(d("0.1"), 15), "0.100000000000000");
        assert_eq!(format_result(d("1"), 99), format_result(d("1"), 15));
    }

    #[test]
    fn large_results_format_without_panicking() {
        // rust_decimal's `{:.15}` overflows a fixed buffer and panics on a 29-digit
        // value; found by the parity table. Zeros are now padded by hand.
        let max = format!("{}.{}", Decimal::MAX, "0".repeat(15));
        assert_eq!(format_result(Decimal::MAX, 15), max);
        assert_eq!(format_result(Decimal::MIN, 15), format!("-{max}"));
        assert_eq!(format_result(Decimal::MAX, 0), Decimal::MAX.to_string());
        assert_eq!(format_result(Decimal::new(1, 28), 15), "0.000000000000000");
        assert_eq!(format_result(Decimal::new(-15, 1), 3), "-1.500");
    }
}
