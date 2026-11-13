//! Static check of a declared migration's statements.
//!
//! An expansion may only add what an older release ignores: new tables,
//! views and non-unique indexes; nullable or defaulted columns on existing
//! tables; rows in its own new tables; and backfills of the columns it adds.
//! Anything that removes, renames or retypes, or that could refuse a row an
//! older release writes or deletes (a unique index or trigger on an existing
//! table, a foreign key that blocks deletes, a CHECK on an added column), is
//! refused. A contraction may change anything except SQLite and declaration
//! bookkeeping; its reader floor and the update's rollback rehearsal guard it.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail, ensure};

use super::{Class, DECLARATIONS_TABLE, INCOMPATIBLE};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    /// A bare word: keyword or identifier (upper-cased for comparison).
    Word(String),
    /// A quoted identifier, lower-cased.
    Quoted(String),
    /// A string or blob literal.
    Literal,
    Punct(char),
}

impl Token {
    fn is(&self, keyword: &str) -> bool {
        matches!(self, Token::Word(word) if word == keyword)
    }

    fn identifier(&self) -> Option<String> {
        match self {
            Token::Word(word) => Some(word.to_lowercase()),
            Token::Quoted(name) => Some(name.clone()),
            _ => None,
        }
    }
}

fn tokenize(sql: &str) -> Result<Vec<Vec<Token>>> {
    let bytes = sql.as_bytes();
    let mut statements = Vec::new();
    let mut current = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        match byte {
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let end = sql[i + 2..]
                    .find("*/")
                    .ok_or_else(|| anyhow::anyhow!("unterminated comment"))?;
                i += end + 4;
            }
            b'\'' | b'"' | b'`' | b'[' => {
                let close = if byte == b'[' { b']' } else { byte };
                let mut text = String::new();
                i += 1;
                loop {
                    ensure!(i < bytes.len(), "unterminated quote");
                    if bytes[i] == close {
                        if close != b']' && bytes.get(i + 1) == Some(&close) {
                            text.push(close as char);
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    text.push(bytes[i] as char);
                    i += 1;
                }
                i += 1;
                current.push(if byte == b'\'' {
                    Token::Literal
                } else {
                    Token::Quoted(text.to_lowercase())
                });
            }
            b';' => {
                if !current.is_empty() {
                    statements.push(std::mem::take(&mut current));
                }
                i += 1;
            }
            _ if byte.is_ascii_whitespace() => i += 1,
            _ if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
                {
                    i += 1;
                }
                if (bytes[start] == b'x' || bytes[start] == b'X')
                    && i == start + 1
                    && bytes.get(i) == Some(&b'\'')
                {
                    // A blob literal X'..': the quote follows as a literal.
                    continue;
                }
                current.push(Token::Word(sql[start..i].to_uppercase()));
            }
            _ => {
                current.push(Token::Punct(byte as char));
                i += 1;
            }
        }
    }
    if !current.is_empty() {
        statements.push(current);
    }
    Ok(statements)
}

fn word(statement: &[Token], index: usize) -> &str {
    match statement.get(index) {
        Some(Token::Word(word)) => word,
        _ => "",
    }
}

/// The table name at `index`, refusing a schema-qualified name.
fn table_at(statement: &[Token], index: usize) -> Result<String> {
    let name = statement
        .get(index)
        .and_then(Token::identifier)
        .ok_or_else(|| anyhow::anyhow!("missing table name"))?;
    ensure!(
        statement.get(index + 1) != Some(&Token::Punct('.')),
        "schema-qualified name {name}"
    );
    Ok(name)
}

/// Every `REFERENCES parent` must let the parent's rows go (`ON DELETE
/// CASCADE` or `SET NULL`) unless the parent is new in this migration.
fn check_references(statement: &[Token], created: &BTreeSet<String>) -> Result<()> {
    for (index, token) in statement.iter().enumerate() {
        if !token.is("REFERENCES") {
            continue;
        }
        let parent = table_at(statement, index + 1)?;
        if created.contains(&parent) {
            continue;
        }
        let mut position = index + 2;
        if statement.get(position) == Some(&Token::Punct('(')) {
            while position < statement.len() && statement[position] != Token::Punct(')') {
                position += 1;
            }
            position += 1;
        }
        let mut depth = 0i32;
        let mut releases = false;
        while position < statement.len() {
            match &statement[position] {
                Token::Punct('(') => depth += 1,
                Token::Punct(')') if depth == 0 => break,
                Token::Punct(')') => depth -= 1,
                Token::Punct(',') if depth == 0 => break,
                token if token.is("ON") && word(statement, position + 1) == "DELETE" => {
                    releases = word(statement, position + 2) == "CASCADE"
                        || (word(statement, position + 2) == "SET"
                            && word(statement, position + 3) == "NULL");
                }
                _ => {}
            }
            position += 1;
        }
        ensure!(
            releases,
            "a reference to {parent} must say ON DELETE CASCADE or ON DELETE SET NULL"
        );
    }
    Ok(())
}

fn expand_statement(
    statement: &[Token],
    created: &mut BTreeSet<String>,
    added: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    let (first, second) = (word(statement, 0), word(statement, 1));
    let skip_if_not_exists = |index: usize| {
        if word(statement, index) == "IF"
            && word(statement, index + 1) == "NOT"
            && word(statement, index + 2) == "EXISTS"
        {
            index + 3
        } else {
            index
        }
    };
    match (first, second) {
        ("CREATE", "TABLE") => {
            let name = table_at(statement, skip_if_not_exists(2))?;
            ensure!(
                !statement.iter().any(|token| token.is("AS")),
                "CREATE TABLE ... AS SELECT copies data; create the table and insert instead"
            );
            created.insert(name);
            check_references(statement, created)
        }
        ("CREATE", "VIEW") => Ok(()),
        ("CREATE", "INDEX") | ("CREATE", "UNIQUE") => {
            let unique = second == "UNIQUE";
            ensure!(
                !unique || word(statement, 2) == "INDEX",
                "unexpected CREATE UNIQUE form"
            );
            let on = statement
                .iter()
                .position(|token| token.is("ON"))
                .ok_or_else(|| anyhow::anyhow!("index without ON"))?;
            let table = table_at(statement, on + 1)?;
            ensure!(
                !unique || created.contains(&table),
                "a unique index on existing table {table} could refuse an older release's rows"
            );
            Ok(())
        }
        ("ALTER", "TABLE") => {
            let table = table_at(statement, 2)?;
            ensure!(
                word(statement, 3) == "ADD",
                "ALTER TABLE {table} may only ADD a column (renames and drops are contractions)"
            );
            let column_at = if word(statement, 4) == "COLUMN" { 5 } else { 4 };
            let column = statement
                .get(column_at)
                .and_then(Token::identifier)
                .ok_or_else(|| anyhow::anyhow!("ADD COLUMN without a name"))?;
            let definition = &statement[column_at + 1..];
            for refused in ["CHECK", "PRIMARY", "UNIQUE", "GENERATED", "AS"] {
                ensure!(
                    !definition.iter().any(|token| token.is(refused)),
                    "added column {table}.{column} may not use {refused}"
                );
            }
            let not_null = definition
                .windows(2)
                .any(|pair| pair[0].is("NOT") && pair[1].is("NULL"));
            ensure!(
                !not_null || definition.iter().any(|token| token.is("DEFAULT")),
                "added column {table}.{column} is NOT NULL without a DEFAULT"
            );
            check_references(statement, created)?;
            added.entry(table).or_default().insert(column);
            Ok(())
        }
        ("INSERT", _) => {
            let into = statement
                .iter()
                .position(|token| token.is("INTO"))
                .ok_or_else(|| anyhow::anyhow!("INSERT without INTO"))?;
            ensure!(
                !statement[..into].iter().any(|token| token.is("REPLACE")),
                "INSERT OR REPLACE deletes rows"
            );
            let table = table_at(statement, into + 1)?;
            ensure!(
                created.contains(&table),
                "an expansion may insert only into the tables it creates, not {table}"
            );
            Ok(())
        }
        ("UPDATE", _) => {
            let mut index = 1;
            if word(statement, 1) == "OR" {
                ensure!(
                    word(statement, 2) != "REPLACE",
                    "UPDATE OR REPLACE deletes rows"
                );
                index = 3;
            }
            let table = table_at(statement, index)?;
            ensure!(word(statement, index + 1) == "SET", "UPDATE without SET");
            if created.contains(&table) {
                return Ok(());
            }
            let allowed = added.get(&table).cloned().unwrap_or_default();
            let mut targets = Vec::new();
            let mut depth = 0i32;
            let mut expect_target = true;
            for token in &statement[index + 2..] {
                match token {
                    Token::Punct('(') => {
                        depth += 1;
                        continue;
                    }
                    Token::Punct(')') => {
                        depth -= 1;
                        continue;
                    }
                    Token::Punct(',') if depth == 0 => {
                        expect_target = true;
                        continue;
                    }
                    Token::Punct('=') if depth <= 1 => {
                        expect_target = false;
                        continue;
                    }
                    token
                        if depth == 0
                            && ["WHERE", "FROM", "RETURNING", "ORDER", "LIMIT"]
                                .iter()
                                .any(|keyword| token.is(keyword)) =>
                    {
                        break;
                    }
                    _ => {}
                }
                if expect_target && depth <= 1 {
                    if let Some(name) = token.identifier() {
                        targets.push(name);
                    }
                }
            }
            ensure!(!targets.is_empty(), "UPDATE {table} sets nothing");
            for target in targets {
                ensure!(
                    allowed.contains(&target),
                    "an expansion may only backfill the columns it adds, not {table}.{target}"
                );
            }
            Ok(())
        }
        _ => bail!(
            "`{first} {second}` is not additive; drops, deletes, renames, triggers, \
             pragmas and transaction control belong to no expansion"
        ),
    }
}

/// Refuses statements a declared migration of `class` may not contain.
pub fn lint(version: i64, sql: &str, class: &Class) -> Result<()> {
    let checked = (|| -> Result<()> {
        ensure!(
            !sql.lines()
                .any(|line| line.trim_start().starts_with("-- no-transaction")),
            "a declared migration runs in one transaction (no `-- no-transaction`)"
        );
        let statements = tokenize(sql)?;
        ensure!(!statements.is_empty(), "the migration is empty");
        let mut created = BTreeSet::new();
        let mut added = BTreeMap::new();
        for statement in &statements {
            for token in statement {
                if let Some(name) = token.identifier() {
                    ensure!(
                        name != "_sqlx_migrations" && name != DECLARATIONS_TABLE,
                        "migrations may not touch SQLx or declaration bookkeeping"
                    );
                }
            }
            let first = word(statement, 0);
            ensure!(
                !matches!(
                    first,
                    "PRAGMA"
                        | "ATTACH"
                        | "DETACH"
                        | "VACUUM"
                        | "BEGIN"
                        | "COMMIT"
                        | "END"
                        | "ROLLBACK"
                        | "SAVEPOINT"
                        | "RELEASE"
                ),
                "`{first}` is not allowed in a migration"
            );
            ensure!(
                !(first == "CREATE"
                    && statement.iter().take(4).any(|token| token.is("TRIGGER")
                        || token.is("TEMP")
                        || token.is("TEMPORARY"))),
                "triggers and temporary objects are not allowed in a migration"
            );
            if *class == Class::Expand {
                expand_statement(statement, &mut created, &mut added)?;
            }
        }
        Ok(())
    })();
    checked.map_err(|error| {
        anyhow::anyhow!(
            "{INCOMPATIBLE}: {} migration {version}: {error}",
            class.name()
        )
    })
}
