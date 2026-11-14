//! libyaml's error and mark types, with the exact `Display`/`Debug` text serde_yaml_ng 0.10 gave
//! them (`src/libyaml/error.rs` there), so every message the product prints is unchanged.

use std::fmt::{self, Debug, Display};

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Memory,
    Reader,
    Scanner,
    Parser,
    Emitter,
    /// A state this port considers impossible; never produced by libyaml.
    Internal,
}

#[derive(Clone)]
pub(crate) struct Error {
    kind: Kind,
    problem: &'static str,
    problem_offset: u64,
    problem_mark: Mark,
    context: Option<&'static str>,
    context_mark: Mark,
}

impl Error {
    fn new(kind: Kind, problem: &'static str) -> Self {
        Error {
            kind,
            problem,
            problem_offset: 0,
            problem_mark: Mark::ZERO,
            context: None,
            context_mark: Mark::ZERO,
        }
    }

    /// libyaml `yaml_parser_set_reader_error`: an offset, no mark.
    pub fn reader(problem: &'static str, offset: u64, _value: i32) -> Self {
        Error {
            problem_offset: offset,
            ..Error::new(Kind::Reader, problem)
        }
    }

    /// libyaml `yaml_parser_set_scanner_error`.
    pub fn scanner(
        context: Option<&'static str>,
        context_mark: Mark,
        problem: &'static str,
        problem_mark: Mark,
    ) -> Self {
        Error {
            problem_mark,
            context,
            context_mark,
            ..Error::new(Kind::Scanner, problem)
        }
    }

    /// libyaml `yaml_parser_set_parser_error`.
    pub fn parser(problem: &'static str, problem_mark: Mark) -> Self {
        Error {
            problem_mark,
            ..Error::new(Kind::Parser, problem)
        }
    }

    /// libyaml `yaml_parser_set_parser_error_context`.
    pub fn parser_context(
        context: &'static str,
        context_mark: Mark,
        problem: &'static str,
        problem_mark: Mark,
    ) -> Self {
        Error {
            problem_mark,
            context: Some(context),
            context_mark,
            ..Error::new(Kind::Parser, problem)
        }
    }

    /// libyaml's emitter errors carry only a problem.
    pub fn emitter(problem: &'static str) -> Self {
        Error::new(Kind::Emitter, problem)
    }

    pub fn memory() -> Self {
        Error::new(Kind::Memory, "memory error")
    }

    pub fn internal(problem: &'static str) -> Self {
        Error::new(Kind::Internal, problem)
    }

    pub fn mark(&self) -> Mark {
        self.problem_mark
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self.problem)?;
        if self.problem_mark.line != 0 || self.problem_mark.column != 0 {
            write!(formatter, " at {}", self.problem_mark)?;
        } else if self.problem_offset != 0 {
            write!(formatter, " at position {}", self.problem_offset)?;
        }
        if let Some(context) = &self.context {
            write!(formatter, ", {}", context)?;
            if (self.context_mark.line != 0 || self.context_mark.column != 0)
                && (self.context_mark.line != self.problem_mark.line
                    || self.context_mark.column != self.problem_mark.column)
            {
                write!(formatter, " at {}", self.context_mark)?;
            }
        }
        Ok(())
    }
}

impl Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let mut formatter = formatter.debug_struct("Error");
        if let Some(kind) = match self.kind {
            Kind::Memory => Some("MEMORY"),
            Kind::Reader => Some("READER"),
            Kind::Scanner => Some("SCANNER"),
            Kind::Parser => Some("PARSER"),
            Kind::Emitter => Some("EMITTER"),
            Kind::Internal => None,
        } {
            formatter.field("kind", &format_args!("{}", kind));
        }
        formatter.field("problem", &self.problem);
        if self.problem_mark.line != 0 || self.problem_mark.column != 0 {
            formatter.field("problem_mark", &self.problem_mark);
        } else if self.problem_offset != 0 {
            formatter.field("problem_offset", &self.problem_offset);
        }
        if let Some(context) = &self.context {
            formatter.field("context", context);
            if self.context_mark.line != 0 || self.context_mark.column != 0 {
                formatter.field("context_mark", &self.context_mark);
            }
        }
        formatter.finish()
    }
}

/// A position in the input: byte `index`, 0-based `line`, and 0-based `column` in characters.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) struct Mark {
    pub(crate) index: u64,
    pub(crate) line: u64,
    pub(crate) column: u64,
}

impl Mark {
    pub(crate) const ZERO: Mark = Mark {
        index: 0,
        line: 0,
        column: 0,
    };

    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn line(&self) -> u64 {
        self.line
    }

    pub fn column(&self) -> u64 {
        self.column
    }
}

impl Display for Mark {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        if self.line != 0 || self.column != 0 {
            write!(
                formatter,
                "line {} column {}",
                self.line + 1,
                self.column + 1
            )
        } else {
            write!(formatter, "position {}", self.index)
        }
    }
}

impl Debug for Mark {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let mut formatter = formatter.debug_struct("Mark");
        if self.line != 0 || self.column != 0 {
            formatter.field("line", &(self.line + 1));
            formatter.field("column", &(self.column + 1));
        } else {
            formatter.field("index", &self.index);
        }
        formatter.finish()
    }
}
