use log::trace;

#[derive(Clone)]
struct Scanner {
    cursor: usize,
    characters: Vec<char>,
}

impl std::fmt::Debug for Scanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Scanner: {}",
            &self.characters.iter().copied().collect::<String>()
        )?;
        write!(
            f,
            "         {}^",
            String::from_utf8(vec![b'.'; self.cursor]).unwrap()
        )
    }
}

impl Scanner {
    pub fn new(string: &str) -> Self {
        trace!("scanning `{string}`");
        Self {
            cursor: 0,
            characters: string.chars().collect(),
        }
    }

    const fn cursor(&self) -> usize {
        self.cursor
    }

    fn peek(&self) -> Option<&char> {
        self.characters.get(self.cursor)
    }

    fn pop(&mut self) -> Option<&char> {
        match self.characters.get(self.cursor) {
            Some(character) => {
                self.cursor += 1;

                Some(character)
            }
            None => None,
        }
    }

    fn scan<T>(
        &mut self,
        cb: impl Fn(&str) -> Option<Action<T>>,
    ) -> std::result::Result<Option<T>, Error> {
        let mut sequence = String::new();
        let mut require = false;
        let mut request = None;

        loop {
            if let Some(target) = self.characters.get(self.cursor) {
                sequence.push(*target);

                match cb(&sequence) {
                    Some(Action::Return(result)) => {
                        self.cursor += 1;

                        break Ok(Some(result));
                    }
                    Some(Action::Request(result)) => {
                        self.cursor += 1;

                        require = false;
                        request = Some(result);
                    }
                    Some(Action::Require) => {
                        self.cursor += 1;

                        require = true;
                    }
                    None => {
                        if require {
                            break Err(Error::Character(self.cursor));
                        }
                        break Ok(request);
                    }
                }
            } else {
                if require {
                    break Err(Error::EndOfSymbol);
                }
                break Ok(request);
            }
        }
    }
}

/// based on "ContentDirectory:1 Service Template" section 2.5.5 Search Criteria
pub fn parse_search_criteria(input: &str) -> std::result::Result<Option<SearchCrit>, Error> {
    let mut scanner = Scanner::new(input);
    search_crit(&mut scanner)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Character(usize),
    EndOfSymbol,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Character(i) => write!(f, "invalid character encountered at {i}"),
            Self::EndOfSymbol => write!(f, "end of symbol reached unexpectedly"),
        }
    }
}

impl std::error::Error for Error {}

enum Action<T> {
    Request(T),
    Require,
    Return(T),
}

#[derive(Debug, PartialEq, Eq)]
pub enum SearchCrit {
    All,
    SearchExp(SearchExp),
}

/// searchCrit = searchExp | asterisk
/// asterisk = ‘*’ (* UTF-8 code 0x2A, asterisk character *)
///
/// The special value ‘*’ means “find everything”, or “return all objects that exist beneath the
/// selected starting container”.
fn search_crit(scanner: &mut Scanner) -> std::result::Result<Option<SearchCrit>, Error> {
    match scanner.peek() {
        Some('*') => {
            scanner.pop();
            Ok(Some(SearchCrit::All))
        }
        Some(_) => match search_exp(scanner) {
            Ok(Some(exp)) => Ok(Some(SearchCrit::SearchExp(exp))),
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        },
        None => Ok(None),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SearchExp {
    Rel(RelExp),
    Log(Box<Self>, LogOp, Box<Self>),
    Brackets(Box<Self>),
}

/// searchExp = relExp | searchExp wChar+ logOp wChar+ searchExp | ‘(’ wChar* searchExp wChar* ‘)’
///
/// Operator precedence, highest to lowest:
///  - dQuote
///  - ( )
///  - binOp, existsOp
///  - and
///  - or
fn search_exp(scanner: &mut Scanner) -> std::result::Result<Option<SearchExp>, Error> {
    search_or(scanner)
}

fn search_or(scanner: &mut Scanner) -> std::result::Result<Option<SearchExp>, Error> {
    match search_and(scanner) {
        Ok(Some(mut left)) => {
            loop {
                wchar(scanner);
                match log_op(&mut scanner.clone()) {
                    Ok(Some(LogOp::Or)) => {
                        log_op(scanner).unwrap();
                        wchar(scanner);

                        match search_and(scanner) {
                            Ok(Some(exp)) => {
                                left = SearchExp::Log(Box::new(left), LogOp::Or, Box::new(exp));
                            }
                            Ok(None) => return Ok(None),
                            Err(err) => return Err(err),
                        }
                    }
                    Ok(Some(_)) => {
                        // back out with what we've got
                        return Ok(Some(left));
                    }
                    Ok(None) => return Ok(Some(left)),
                    Err(err) => return Err(err),
                }
            }
        }
        Ok(None) => Ok(None),
        Err(err) => Err(err),
    }
}

fn search_and(scanner: &mut Scanner) -> std::result::Result<Option<SearchExp>, Error> {
    match search_core(scanner) {
        Ok(Some(mut left)) => {
            loop {
                wchar(scanner);
                match log_op(&mut scanner.clone()) {
                    Ok(Some(LogOp::And)) => {
                        log_op(scanner).unwrap();
                        wchar(scanner);

                        match search_core(scanner) {
                            Ok(Some(exp)) => {
                                left = SearchExp::Log(Box::new(left), LogOp::And, Box::new(exp));
                            }
                            Ok(None) => return Ok(None),
                            Err(err) => return Err(err),
                        }
                    }
                    Ok(Some(LogOp::Or)) => {
                        // back out with what we've got
                        return Ok(Some(left));
                    }
                    Ok(None) => return Ok(Some(left)),
                    Err(err) => return Err(err),
                }
            }
        }
        Ok(None) => Ok(None),
        Err(err) => Err(err),
    }
}

fn search_core(scanner: &mut Scanner) -> std::result::Result<Option<SearchExp>, Error> {
    match scanner.peek() {
        Some('(') => {
            scanner.pop();
            match search_exp(scanner) {
                Ok(Some(exp)) => match scanner.pop() {
                    Some(')') => Ok(Some(SearchExp::Brackets(Box::new(exp)))),
                    _ => Err(Error::Character(scanner.cursor())),
                },
                _ => Err(Error::Character(scanner.cursor())),
            }
        }
        Some(_) => {
            let mut test_scanner = scanner.clone();
            if let Ok(Some(exp)) = rel_exp(&mut test_scanner) {
                rel_exp(scanner).unwrap(); // we just tested this works
                Ok(Some(SearchExp::Rel(exp)))
            } else {
                Err(Error::Character(scanner.cursor()))
            }
        }
        None => Ok(None),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LogOp {
    And,
    Or,
}

/// logOp = ‘and’ | ‘or’
fn log_op(scanner: &mut Scanner) -> std::result::Result<Option<LogOp>, Error> {
    scanner.scan(|symbol| match symbol {
        "a" | "an" | "o" => Some(Action::Require),
        "and" => Some(Action::Return(LogOp::And)),
        "or" => Some(Action::Return(LogOp::Or)),
        _ => None,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum RelExp {
    BinOp(String, BinOp, QuotedVal),
    ExistsOp(String, ExistsOp, BoolVal),
}

/// relExp = property wChar+ binOp wChar+ quotedVal | property wChar+ existsOp wChar+ boolVal
/// property = (* property name as defined in section 2.4 *)
///
/// Property existence testing. Property existence is queried for by using the ‘exists’ operator.
/// Strictly speaking, ‘exists’ could be a unary operator. This searchCriteria syntax makes it a
/// binary operator to simplify search string parsing—there are no unary operators. The string
/// "actor exists true" is true for every object that has at least one occurrence of the actor
/// property. It is false for any object that has no actor property. Similarly, the string "actor
/// exists false" is false for every object that has at least one occurrence of the actor property.
/// It is true for any object that has no actor property.
///
/// Property omission. Any property value query (as distinct from an existence query) applied to an
/// object that does not have that property, evaluates to false.
///
/// Numeric comparisons. When the operator in a relExp is a relOp, and both the escapedQuote value
/// and the actual property value are sequences of decimal digits or sequences of decimal digits
/// preceded by either a ‘+’ or ‘-’ sign (i.e., integers), the comparison is done numerically. For
/// all other combinations of operators and property values, the comparison is done by treating
/// both values as strings, converting a numeric value to its string representation in decimal if
/// necessary.
/// Note: The CDS is not expected to recognize any kind of numeric data other than decimal
/// integers, composed only of decimal digits with the optional leading sign.
fn rel_exp(scanner: &mut Scanner) -> std::result::Result<Option<RelExp>, Error> {
    #[derive(Debug)]
    enum BinOrExists {
        Bin(BinOp),
        Exists(ExistsOp),
    }

    let mut sequence = String::new();
    let property = loop {
        match scanner.peek().copied() {
            Some(c) if c.is_whitespace() => {
                // TODO lets have lots of whitespace ok
                scanner.pop();
                break sequence;
            }
            Some(c) => {
                scanner.pop();
                sequence.push(c);
            }
            None => {
                if sequence.is_empty() {
                    return Ok(None);
                }
                return Err(Error::EndOfSymbol);
            }
        }
    };

    let bin_or_exists = if let Ok(Some(res)) = bin_op(&mut scanner.clone()) {
        bin_op(scanner).unwrap(); // we just tested this works
        BinOrExists::Bin(res)
    } else if let Ok(Some(res)) = exists_op(&mut scanner.clone()) {
        exists_op(scanner).unwrap(); // we just tested this works
        BinOrExists::Exists(res)
    } else {
        return Ok(None);
    };

    wchar(scanner);

    match bin_or_exists {
        BinOrExists::Bin(op) => match quoted_val(scanner) {
            Ok(Some(val)) => Ok(Some(RelExp::BinOp(property, op, val))),
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        },
        BinOrExists::Exists(op) => match bool_val(scanner) {
            Ok(Some(val)) => Ok(Some(RelExp::ExistsOp(property, op, val))),
            Ok(None) => Ok(None),
            Err(err) => Err(err),
        },
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BinOp {
    RelOp(RelOp),
    StringOp(StringOp),
}

/// binOp = relOp | stringOp
/// TODO: figure out how to not scan twice...
fn bin_op(scanner: &mut Scanner) -> std::result::Result<Option<BinOp>, Error> {
    if let Ok(Some(_res)) = rel_op(&mut scanner.clone()) {
        rel_op(scanner).map(|op| op.map(BinOp::RelOp))
    } else if let Ok(Some(_res)) = string_op(&mut scanner.clone()) {
        string_op(scanner).map(|op| op.map(BinOp::StringOp))
    } else {
        Ok(None)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RelOp {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

/// relOp = ‘=’ | ‘!=’ | ‘<’ | ‘<=’ | ‘>’ | ‘>=’
fn rel_op(scanner: &mut Scanner) -> std::result::Result<Option<RelOp>, Error> {
    scanner.scan(|symbol| match symbol {
        "=" => Some(Action::Return(RelOp::Equal)),
        "!" => Some(Action::Require),
        "!=" => Some(Action::Return(RelOp::NotEqual)),
        "<" => Some(Action::Request(RelOp::Less)),
        "<=" => Some(Action::Return(RelOp::LessEqual)),
        ">" => Some(Action::Request(RelOp::Greater)),
        ">=" => Some(Action::Return(RelOp::GreaterEqual)),
        _ => None,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum StringOp {
    Contains,
    DoesNotContain,
    DerivedFrom,
}

/// stringOp = ‘contains’ | ‘doesNotContain’ | ‘derivedfrom’
///
/// Class derivation testing. Existence of objects whose class is derived from some base class
/// specification is queried for by using the ‘derivedfrom’ operator.
fn string_op(scanner: &mut Scanner) -> std::result::Result<Option<StringOp>, Error> {
    scanner.scan(|symbol| match symbol {
        "c" | "d" | "co" | "con" | "cont" | "conta" | "contai" | "contain" | "do" | "doe"
        | "does" | "doesN" | "doesNo" | "doesNot" | "doesNotC" | "doesNotCo" | "doesNotCon"
        | "doesNotCont" | "doesNotConta" | "doesNotContai" | "de" | "der" | "deri" | "deriv"
        | "derive" | "derived" | "derivedf" | "derivedfr" | "derivedfro" => Some(Action::Require),
        "contains" => Some(Action::Return(StringOp::Contains)),
        "doesNotContain" => Some(Action::Return(StringOp::DoesNotContain)),
        "derivedfrom" => Some(Action::Return(StringOp::DerivedFrom)),
        _ => None,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExistsOp {
    Exists,
}

/// existsOp = ‘exists’
fn exists_op(scanner: &mut Scanner) -> std::result::Result<Option<ExistsOp>, Error> {
    scanner.scan(|symbol| match symbol {
        "e" | "ex" | "exi" | "exis" | "exist" => Some(Action::Require),
        "exists" => Some(Action::Return(ExistsOp::Exists)),
        _ => None,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum BoolVal {
    True,
    False,
}

/// boolVal = ‘true’ | ‘false’
fn bool_val(scanner: &mut Scanner) -> std::result::Result<Option<BoolVal>, Error> {
    scanner.scan(|symbol| match symbol {
        "t" | "tr" | "tru" | "f" | "fa" | "fal" | "fals" => Some(Action::Require),
        "true" => Some(Action::Return(BoolVal::True)),
        "false" => Some(Action::Return(BoolVal::False)),
        _ => None,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum QuotedVal {
    String(String),
}

/// quotedVal = dQuote escapedQuote dQuote
/// escapedQuote  = (* double-quote escaped string as defined in section 2.3.1 *)
/// dQuote = ‘"’ (* UTF-8 code 0x22, double quote character *)
///
/// String comparisons. All operators when applied to strings use case-insensitive comparisons.
fn quoted_val(scanner: &mut Scanner) -> std::result::Result<Option<QuotedVal>, Error> {
    let mut sequence = String::new();

    match scanner.peek() {
        Some('"') => scanner.pop(),
        _ => return Ok(None),
    };

    loop {
        match scanner.peek().copied() {
            Some(target) => {
                scanner.pop();

                match target {
                    '"' => {
                        break Ok(Some(QuotedVal::String(sequence)));
                    }
                    c => {
                        sequence.push(c);
                    }
                }
            }
            None => {
                break Err(Error::EndOfSymbol);
            }
        }
    }
}

enum WChar {
    WChar,
}

/// wChar = space | hTab | lineFeed | vTab | formFeed | return
/// hTab = (* UTF-8 code 0x09, horizontal tab character *)
/// lineFeed = (* UTF-8 code 0x0A, line feed character *)
/// vTab = (* UTF-8 code 0x0B, vertical tab character *)
/// formFeed = (* UTF-8 code 0x0C, form feed character *)
/// return = (* UTF-8 code 0x0D, carriage return character *)
/// space = ‘ ’ (* UTF-8 code 0x20, space character *)
fn wchar(scanner: &mut Scanner) -> Option<WChar> {
    let mut wchar = None;
    loop {
        match scanner.peek() {
            Some(c) if c.is_whitespace() => {
                scanner.pop();
                wchar = Some(WChar::WChar);
            }
            _ => {
                break wchar;
            }
        }
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn test_search_exp() {
        assert_eq!(
            search_exp(&mut Scanner::new("title contains \"xyz\"")),
            Ok(Some(SearchExp::Rel(RelExp::BinOp(
                "title".to_string(),
                BinOp::StringOp(StringOp::Contains),
                QuotedVal::String("xyz".to_string())
            ))))
        );
        assert_eq!(
            search_exp(&mut Scanner::new(
                "date exists true and title contains \"xyz\""
            )),
            Ok(Some(SearchExp::Log(
                Box::new(SearchExp::Rel(RelExp::ExistsOp(
                    "date".to_string(),
                    ExistsOp::Exists,
                    BoolVal::True,
                ))),
                LogOp::And,
                Box::new(SearchExp::Rel(RelExp::BinOp(
                    "title".to_string(),
                    BinOp::StringOp(StringOp::Contains),
                    QuotedVal::String("xyz".to_string())
                ))),
            )))
        );
        assert_eq!(
            search_exp(&mut Scanner::new("(title contains \"xyz\")")),
            Ok(Some(SearchExp::Brackets(Box::new(SearchExp::Rel(
                RelExp::BinOp(
                    "title".to_string(),
                    BinOp::StringOp(StringOp::Contains),
                    QuotedVal::String("xyz".to_string())
                )
            )))))
        );
        assert_eq!(
            search_exp(&mut Scanner::new("((title contains \"xyz\"))")),
            Ok(Some(SearchExp::Brackets(Box::new(SearchExp::Brackets(
                Box::new(SearchExp::Rel(RelExp::BinOp(
                    "title".to_string(),
                    BinOp::StringOp(StringOp::Contains),
                    QuotedVal::String("xyz".to_string())
                )))
            )))))
        );
        // TODO test some bad stuff?
    }

    #[test]
    fn test_log_op() {
        assert_eq!(log_op(&mut Scanner::new("and")), Ok(Some(LogOp::And)));
        assert_eq!(log_op(&mut Scanner::new("aX")), Err(Error::Character(1)));
        assert_eq!(log_op(&mut Scanner::new("anX")), Err(Error::Character(2)));
        assert_eq!(log_op(&mut Scanner::new("or")), Ok(Some(LogOp::Or)));
        assert_eq!(log_op(&mut Scanner::new("o")), Err(Error::EndOfSymbol));
        assert_eq!(log_op(&mut Scanner::new("not")), Ok(None));
    }

    #[test]
    fn test_rel_exp() {
        assert_eq!(
            rel_exp(&mut Scanner::new("title contains \"xyz\"")),
            Ok(Some(RelExp::BinOp(
                "title".to_string(),
                BinOp::StringOp(StringOp::Contains),
                QuotedVal::String("xyz".to_string())
            )))
        );
        assert_eq!(
            rel_exp(&mut Scanner::new("date exists true")),
            Ok(Some(RelExp::ExistsOp(
                "date".to_string(),
                ExistsOp::Exists,
                BoolVal::True,
            )))
        );
        // TODO test some bad stuff?
    }

    #[test]
    fn test_bin_op() {
        assert_eq!(
            bin_op(&mut Scanner::new("=")),
            Ok(Some(BinOp::RelOp(RelOp::Equal)))
        );
        assert_eq!(
            bin_op(&mut Scanner::new("contains")),
            Ok(Some(BinOp::StringOp(StringOp::Contains)))
        );
    }

    #[test]
    fn test_rel_op() {
        assert_eq!(rel_op(&mut Scanner::new("=")), Ok(Some(RelOp::Equal)));
        assert_eq!(rel_op(&mut Scanner::new("!=")), Ok(Some(RelOp::NotEqual)));
        assert_eq!(rel_op(&mut Scanner::new("<")), Ok(Some(RelOp::Less)));
        assert_eq!(rel_op(&mut Scanner::new("<=")), Ok(Some(RelOp::LessEqual)));
        assert_eq!(rel_op(&mut Scanner::new(">")), Ok(Some(RelOp::Greater)));
        assert_eq!(
            rel_op(&mut Scanner::new(">=")),
            Ok(Some(RelOp::GreaterEqual))
        );
    }

    #[test]
    fn test_string_op() {
        assert_eq!(
            string_op(&mut Scanner::new("contains")),
            Ok(Some(StringOp::Contains))
        );
        assert_eq!(
            string_op(&mut Scanner::new("doesNotContain")),
            Ok(Some(StringOp::DoesNotContain))
        );
        assert_eq!(
            string_op(&mut Scanner::new("derivedfrom")),
            Ok(Some(StringOp::DerivedFrom))
        );
    }

    #[test]
    fn test_exists_op() {
        assert_eq!(
            exists_op(&mut Scanner::new("exists")),
            Ok(Some(ExistsOp::Exists))
        );
    }

    #[test]
    fn test_bool_val() {
        assert_eq!(bool_val(&mut Scanner::new("true")), Ok(Some(BoolVal::True)));
        assert_eq!(
            bool_val(&mut Scanner::new("false")),
            Ok(Some(BoolVal::False))
        );
    }

    #[test]
    fn test_quoted_val() {
        assert_eq!(
            quoted_val(&mut Scanner::new("\"this is the quoted value\"")),
            Ok(Some(QuotedVal::String(
                "this is the quoted value".to_string()
            )))
        );
        assert_eq!(quoted_val(&mut Scanner::new("somethingelse")), Ok(None));
        assert_eq!(
            quoted_val(&mut Scanner::new("\"this is bad")),
            Err(Error::EndOfSymbol)
        );
    }

    #[test]
    fn test_search_crit() {
        assert_eq!(
            search_crit(&mut Scanner::new(r#"*"#)),
            Ok(Some(SearchCrit::All))
        );
        assert_eq!(
            search_crit(&mut Scanner::new(
                r#"upnp:class derivedfrom "object.container.album""#
            )),
            Ok(Some(SearchCrit::SearchExp(SearchExp::Rel(RelExp::BinOp(
                "upnp:class".to_string(),
                BinOp::StringOp(StringOp::DerivedFrom),
                QuotedVal::String("object.container.album".to_string())
            )))))
        );
        assert_eq!(
            search_crit(&mut Scanner::new(
                r#"upnp:class = "object.item.imageItem.photo" and (dc:date >= "2001-10-01" and dc:date <= "2001-10-31" )"#
            )),
            Ok(Some(SearchCrit::SearchExp(SearchExp::Log(
                Box::new(SearchExp::Rel(RelExp::BinOp(
                    "upnp:class".to_string(),
                    BinOp::RelOp(RelOp::Equal),
                    QuotedVal::String("object.item.imageItem.photo".to_string())
                ))),
                LogOp::And,
                Box::new(SearchExp::Brackets(Box::new(SearchExp::Log(
                    Box::new(SearchExp::Rel(RelExp::BinOp(
                        "dc:date".to_string(),
                        BinOp::RelOp(RelOp::GreaterEqual),
                        QuotedVal::String("2001-10-01".to_string())
                    ))),
                    LogOp::And,
                    Box::new(SearchExp::Rel(RelExp::BinOp(
                        "dc:date".to_string(),
                        BinOp::RelOp(RelOp::LessEqual),
                        QuotedVal::String("2001-10-31".to_string())
                    )))
                ))))
            ))))
        );

        assert_eq!(
            search_crit(&mut Scanner::new(
                r#"upnp:class = "object.container.album.musicAlbum" and dc:title contains "lo" and dc:date >= "2001-10-01""#
            )),
            Ok(Some(SearchCrit::SearchExp(SearchExp::Log(
                Box::new(SearchExp::Log(
                    Box::new(SearchExp::Rel(RelExp::BinOp(
                        "upnp:class".to_string(),
                        BinOp::RelOp(RelOp::Equal),
                        QuotedVal::String("object.container.album.musicAlbum".to_string())
                    ))),
                    LogOp::And,
                    Box::new(SearchExp::Rel(RelExp::BinOp(
                        "dc:title".to_string(),
                        BinOp::StringOp(StringOp::Contains),
                        QuotedVal::String("lo".to_string())
                    )))
                )),
                LogOp::And,
                Box::new(SearchExp::Rel(RelExp::BinOp(
                    "dc:date".to_string(),
                    BinOp::RelOp(RelOp::GreaterEqual),
                    QuotedVal::String("2001-10-01".to_string())
                ))),
            ))))
        );
    }

    #[test]
    fn test_real_searches() {
        assert_eq!(
            parse_search_criteria(
                r#"upnp:class = "object.container.person.musicArtist" and (upnp:artist contains "lo" or dc:title contains "lo")"#
            ),
            Ok(Some(SearchCrit::SearchExp(SearchExp::Log(
                Box::new(SearchExp::Rel(RelExp::BinOp(
                    "upnp:class".to_string(),
                    BinOp::RelOp(RelOp::Equal),
                    QuotedVal::String("object.container.person.musicArtist".to_string())
                ))),
                LogOp::And,
                Box::new(SearchExp::Brackets(Box::new(SearchExp::Log(
                    Box::new(SearchExp::Rel(RelExp::BinOp(
                        "upnp:artist".to_string(),
                        BinOp::StringOp(StringOp::Contains),
                        QuotedVal::String("lo".to_string())
                    ))),
                    LogOp::Or,
                    Box::new(SearchExp::Rel(RelExp::BinOp(
                        "dc:title".to_string(),
                        BinOp::StringOp(StringOp::Contains),
                        QuotedVal::String("lo".to_string())
                    )))
                ))))
            ))))
        );

        assert_eq!(
            parse_search_criteria(
                r#"upnp:class = "object.container.album.musicAlbum" and (upnp:album contains "lo" or dc:title contains "lo" or upnp:artist contains "lo")"#,
            ),
            Ok(Some(SearchCrit::SearchExp(SearchExp::Log(
                Box::new(SearchExp::Rel(RelExp::BinOp(
                    "upnp:class".to_string(),
                    BinOp::RelOp(RelOp::Equal),
                    QuotedVal::String("object.container.album.musicAlbum".to_string()),
                ))),
                LogOp::And,
                Box::new(SearchExp::Brackets(Box::new(SearchExp::Log(
                    Box::new(SearchExp::Log(
                        Box::new(SearchExp::Rel(RelExp::BinOp(
                            "upnp:album".to_string(),
                            BinOp::StringOp(StringOp::Contains),
                            QuotedVal::String("lo".to_string()),
                        ))),
                        LogOp::Or,
                        Box::new(SearchExp::Rel(RelExp::BinOp(
                            "dc:title".to_string(),
                            BinOp::StringOp(StringOp::Contains),
                            QuotedVal::String("lo".to_string()),
                        ))),
                    )),
                    LogOp::Or,
                    Box::new(SearchExp::Rel(RelExp::BinOp(
                        "upnp:artist".to_string(),
                        BinOp::StringOp(StringOp::Contains),
                        QuotedVal::String("lo".to_string()),
                    ))),
                )))),
            ))))
        );

        assert_eq!(
            parse_search_criteria(
                r#"upnp:class derivedfrom "object.item.audioItem" and (dc:title contains "lo" or upnp:artist contains "lo" or dc:creator contains "lo")"#,
            ),
            Ok(Some(SearchCrit::SearchExp(SearchExp::Log(
                Box::new(SearchExp::Rel(RelExp::BinOp(
                    "upnp:class".to_string(),
                    BinOp::StringOp(StringOp::DerivedFrom),
                    QuotedVal::String("object.item.audioItem".to_string()),
                ))),
                LogOp::And,
                Box::new(SearchExp::Brackets(Box::new(SearchExp::Log(
                    Box::new(SearchExp::Log(
                        Box::new(SearchExp::Rel(RelExp::BinOp(
                            "dc:title".to_string(),
                            BinOp::StringOp(StringOp::Contains),
                            QuotedVal::String("lo".to_string()),
                        ))),
                        LogOp::Or,
                        Box::new(SearchExp::Rel(RelExp::BinOp(
                            "upnp:artist".to_string(),
                            BinOp::StringOp(StringOp::Contains),
                            QuotedVal::String("lo".to_string()),
                        ))),
                    )),
                    LogOp::Or,
                    Box::new(SearchExp::Rel(RelExp::BinOp(
                        "dc:creator".to_string(),
                        BinOp::StringOp(StringOp::Contains),
                        QuotedVal::String("lo".to_string()),
                    ))),
                )))),
            ))))
        );

        assert_eq!(
            parse_search_criteria(
                r#"upnp:class = "object.container.playlistContainer" and dc:title contains "lo""#
            ),
            Ok(Some(SearchCrit::SearchExp(SearchExp::Log(
                Box::new(SearchExp::Rel(RelExp::BinOp(
                    "upnp:class".to_string(),
                    BinOp::RelOp(RelOp::Equal),
                    QuotedVal::String("object.container.playlistContainer".to_string())
                ))),
                LogOp::And,
                Box::new(SearchExp::Rel(RelExp::BinOp(
                    "dc:title".to_string(),
                    BinOp::StringOp(StringOp::Contains),
                    QuotedVal::String("lo".to_string())
                )))
            ))))
        );
    }
}
