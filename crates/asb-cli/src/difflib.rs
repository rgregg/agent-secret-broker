//! `difflib.unified_diff` for lists of lines, ported from CPython's `SequenceMatcher` (no junk function, with the
//! "popular element" heuristic for 200+ lines), so `asb agent-setup --dry-run` prints the same diff Python does.
//! Checked against tests/fixtures/cli/difflib.json, which tools/gen_cli_golden.py records from Python itself.

use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Match {
    i: usize,
    j: usize,
    size: usize,
}

struct Matcher<'a> {
    a: &'a [&'a str],
    b: &'a [&'a str],
    b2j: HashMap<&'a str, Vec<usize>>,
}

impl<'a> Matcher<'a> {
    fn new(a: &'a [&'a str], b: &'a [&'a str]) -> Self {
        let mut b2j: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, line) in b.iter().enumerate() {
            b2j.entry(line).or_default().push(i);
        }
        // Purge popular elements: with 200 or more lines, anything that appears in more than 1% (plus one) of them.
        if b.len() >= 200 {
            let ntest = b.len() / 100 + 1;
            let popular: HashSet<&str> = b2j
                .iter()
                .filter(|(_, idx)| idx.len() > ntest)
                .map(|(k, _)| *k)
                .collect();
            for p in popular {
                b2j.remove(p);
            }
        }
        Matcher { a, b, b2j }
    }

    fn find_longest_match(&self, alo: usize, ahi: usize, blo: usize, bhi: usize) -> Match {
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for i in alo..ahi {
            let mut newj2len: HashMap<usize, usize> = HashMap::new();
            if let Some(js) = self.b2j.get(self.a[i]) {
                for &j in js {
                    if j < blo {
                        continue;
                    }
                    if j >= bhi {
                        break;
                    }
                    let k = j2len.get(&j.wrapping_sub(1)).copied().unwrap_or(0) + 1;
                    newj2len.insert(j, k);
                    if k > bestsize {
                        besti = i + 1 - k;
                        bestj = j + 1 - k;
                        bestsize = k;
                    }
                }
            }
            j2len = newj2len;
        }
        // extend the best match by identical neighbours, which also recovers the popular lines that were purged
        while besti > alo && bestj > blo && self.a[besti - 1] == self.b[bestj - 1] {
            besti -= 1;
            bestj -= 1;
            bestsize += 1;
        }
        while besti + bestsize < ahi
            && bestj + bestsize < bhi
            && self.a[besti + bestsize] == self.b[bestj + bestsize]
        {
            bestsize += 1;
        }
        Match {
            i: besti,
            j: bestj,
            size: bestsize,
        }
    }

    fn matching_blocks(&self) -> Vec<Match> {
        let (la, lb) = (self.a.len(), self.b.len());
        let mut queue = vec![(0, la, 0, lb)];
        let mut blocks = Vec::new();
        while let Some((alo, ahi, blo, bhi)) = queue.pop() {
            let m = self.find_longest_match(alo, ahi, blo, bhi);
            if m.size > 0 {
                blocks.push(m);
                if alo < m.i && blo < m.j {
                    queue.push((alo, m.i, blo, m.j));
                }
                if m.i + m.size < ahi && m.j + m.size < bhi {
                    queue.push((m.i + m.size, ahi, m.j + m.size, bhi));
                }
            }
        }
        blocks.sort();
        // collapse adjacent blocks
        let (mut i1, mut j1, mut k1) = (0, 0, 0);
        let mut out = Vec::new();
        for m in blocks {
            if i1 + k1 == m.i && j1 + k1 == m.j {
                k1 += m.size;
            } else {
                if k1 > 0 {
                    out.push(Match {
                        i: i1,
                        j: j1,
                        size: k1,
                    });
                }
                (i1, j1, k1) = (m.i, m.j, m.size);
            }
        }
        if k1 > 0 {
            out.push(Match {
                i: i1,
                j: j1,
                size: k1,
            });
        }
        out.push(Match {
            i: la,
            j: lb,
            size: 0,
        });
        out
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tag {
    Equal,
    Replace,
    Delete,
    Insert,
}

type Op = (Tag, usize, usize, usize, usize);

fn opcodes(m: &Matcher) -> Vec<Op> {
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    for b in m.matching_blocks() {
        let tag = if i < b.i && j < b.j {
            Some(Tag::Replace)
        } else if i < b.i {
            Some(Tag::Delete)
        } else if j < b.j {
            Some(Tag::Insert)
        } else {
            None
        };
        if let Some(tag) = tag {
            out.push((tag, i, b.i, j, b.j));
        }
        i = b.i + b.size;
        j = b.j + b.size;
        if b.size > 0 {
            out.push((Tag::Equal, b.i, i, b.j, j));
        }
    }
    out
}

fn grouped_opcodes(m: &Matcher, n: usize) -> Vec<Vec<Op>> {
    let mut codes = opcodes(m);
    if codes.is_empty() {
        codes.push((Tag::Equal, 0, 1, 0, 1));
    }
    if let Some(first) = codes.first_mut() {
        if first.0 == Tag::Equal {
            let (t, i1, i2, j1, j2) = *first;
            *first = (
                t,
                i1.max(i2.saturating_sub(n)),
                i2,
                j1.max(j2.saturating_sub(n)),
                j2,
            );
        }
    }
    if let Some(last) = codes.last_mut() {
        if last.0 == Tag::Equal {
            let (t, i1, i2, j1, j2) = *last;
            *last = (t, i1, i2.min(i1 + n), j1, j2.min(j1 + n));
        }
    }
    let nn = n + n;
    let (mut groups, mut group) = (Vec::new(), Vec::new());
    for (tag, mut i1, i2, mut j1, j2) in codes {
        if tag == Tag::Equal && i2 - i1 > nn {
            group.push((tag, i1, i2.min(i1 + n), j1, j2.min(j1 + n)));
            groups.push(std::mem::take(&mut group));
            i1 = i1.max(i2.saturating_sub(n));
            j1 = j1.max(j2.saturating_sub(n));
        }
        group.push((tag, i1, i2, j1, j2));
    }
    let only_equal = group.len() == 1 && group[0].0 == Tag::Equal;
    if !group.is_empty() && !only_equal {
        groups.push(group);
    }
    groups
}

fn format_range(start: usize, stop: usize) -> String {
    let mut beginning = start + 1; // lines are numbered from one
    let length = stop - start;
    if length == 1 {
        return beginning.to_string();
    }
    if length == 0 {
        beginning -= 1; // an empty range begins at the line just before it
    }
    format!("{beginning},{length}")
}

/// Python's `str.splitlines()`: breaks on `\n`, `\r`, `\r\n`, `\v`, `\f`, `\x1c`-`\x1e`, `\x85`, ` `, ` `.
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut chars) = (0, s.char_indices().peekable());
    while let Some((i, c)) = chars.next() {
        if matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' && chars.peek().is_some_and(|(_, n)| *n == '\n') {
                chars.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `difflib.unified_diff(a.splitlines(), b.splitlines(), from, to, lineterm="")` as a list of lines.
pub fn unified_diff(a: &str, b: &str, from: &str, to: &str) -> Vec<String> {
    let (a_lines, b_lines) = (splitlines(a), splitlines(b));
    let matcher = Matcher::new(&a_lines, &b_lines);
    let mut out = Vec::new();
    for (n, group) in grouped_opcodes(&matcher, 3).iter().enumerate() {
        if n == 0 {
            out.push(format!("--- {from}"));
            out.push(format!("+++ {to}"));
        }
        let (first, last) = (group[0], group[group.len() - 1]);
        out.push(format!(
            "@@ -{} +{} @@",
            format_range(first.1, last.2),
            format_range(first.3, last.4)
        ));
        for &(tag, i1, i2, j1, j2) in group {
            if tag == Tag::Equal {
                out.extend(a_lines[i1..i2].iter().map(|l| format!(" {l}")));
                continue;
            }
            if matches!(tag, Tag::Replace | Tag::Delete) {
                out.extend(a_lines[i1..i2].iter().map(|l| format!("-{l}")));
            }
            if matches!(tag, Tag::Replace | Tag::Insert) {
                out.extend(b_lines[j1..j2].iter().map(|l| format!("+{l}")));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_every_golden_case_recorded_from_python() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/cli/difflib.json"
        );
        let cases: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(cases.len() >= 30);
        for (n, c) in cases.iter().enumerate() {
            let want: Vec<String> = c["diff"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l.as_str().unwrap().to_string())
                .collect();
            let got = unified_diff(
                c["a"].as_str().unwrap(),
                c["b"].as_str().unwrap(),
                c["from"].as_str().unwrap(),
                c["to"].as_str().unwrap(),
            );
            assert_eq!(got, want, "case {n}");
        }
    }

    #[test]
    fn splitlines_matches_python() {
        assert_eq!(splitlines("a\nb\r\nc\rd"), ["a", "b", "c", "d"]);
        assert_eq!(splitlines("a\n"), ["a"]);
        assert_eq!(splitlines(""), Vec::<&str>::new());
        assert_eq!(splitlines("a\n\nb"), ["a", "", "b"]);
        assert_eq!(splitlines("x\u{2028}y\u{85}z"), ["x", "y", "z"]);
    }
}
