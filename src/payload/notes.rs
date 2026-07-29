use std::fmt;

use serde::{Deserialize, Deserializer};
use zeroize::Zeroize;

use crate::{Error, Result};

/// A decoded collection of COLDCARD Secure Notes & Passwords records
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct NotesPayload(Vec<NotesRecord>);

impl NotesPayload {
    /// Returns the decoded records in their transmitted order
    pub fn records(&self) -> &[NotesRecord] {
        &self.0
    }
}

impl fmt::Debug for NotesPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotesPayload").field("record_count", &self.0.len()).finish()
    }
}

/// A decoded COLDCARD secure note or password record
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub enum NotesRecord {
    /// A free-form secure note
    Note(NoteRecord),
    /// A structured password record
    Password(PasswordRecord),
}

impl NotesRecord {
    /// Returns the title shown for this record
    pub fn title(&self) -> &str {
        match self {
            Self::Note(note) => note.title(),
            Self::Password(password) => password.title(),
        }
    }

    /// Returns the optional group shown for this record
    pub fn group(&self) -> &str {
        match self {
            Self::Note(note) => note.group(),
            Self::Password(password) => password.group(),
        }
    }
}

impl fmt::Debug for NotesRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Note(_) => f.write_str("NotesRecord::Note(****)"),
            Self::Password(_) => f.write_str("NotesRecord::Password(****)"),
        }
    }
}

/// A decoded COLDCARD free-form secure note
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct NoteRecord {
    title: String,
    text: String,
    group: String,
}

impl NoteRecord {
    /// Returns the note title
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the free-form note text
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the optional group, or an empty string when absent
    pub fn group(&self) -> &str {
        &self.group
    }
}

impl fmt::Debug for NoteRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoteRecord(****)")
    }
}

/// A decoded COLDCARD structured password record
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct PasswordRecord {
    title: String,
    username: String,
    password: String,
    site: String,
    notes: String,
    group: String,
}

impl PasswordRecord {
    /// Returns the password record title
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the username, or an empty string when absent
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the password, or an empty string when absent
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Returns the site, or an empty string when absent
    pub fn site(&self) -> &str {
        &self.site
    }

    /// Returns the free-form notes, or an empty string when absent
    pub fn notes(&self) -> &str {
        &self.notes
    }

    /// Returns the optional group, or an empty string when absent
    pub fn group(&self) -> &str {
        &self.group
    }
}

impl fmt::Debug for PasswordRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordRecord(****)")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNotesRecord {
    title: String,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    user: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    site: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    misc: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    group: Option<String>,
}

impl Drop for WireNotesRecord {
    fn drop(&mut self) {
        self.title.zeroize();
        self.user.zeroize();
        self.password.zeroize();
        self.site.zeroize();
        self.misc.zeroize();
        self.group.zeroize();
    }
}

pub(super) fn decode_body(body: &[u8]) -> Result<NotesPayload> {
    let mut records: Vec<WireNotesRecord> =
        serde_json::from_slice(body).map_err(|_| Error::InvalidNotesPayload)?;
    if records.is_empty() {
        return Err(Error::InvalidNotesPayload);
    }

    let records = records.iter_mut().map(NotesRecord::try_from).collect::<Result<Vec<_>>>()?;

    Ok(NotesPayload(records))
}

impl TryFrom<&mut WireNotesRecord> for NotesRecord {
    type Error = Error;

    fn try_from(record: &mut WireNotesRecord) -> Result<Self> {
        if record.title.is_empty() {
            return Err(Error::InvalidNotesPayload);
        }

        let is_password = record.user.is_some();
        if !is_password && (record.password.is_some() || record.site.is_some()) {
            return Err(Error::InvalidNotesPayload);
        }

        let group = record.group.take().unwrap_or_default();
        if let Some(username) = record.user.take() {
            return Ok(Self::Password(PasswordRecord {
                title: std::mem::take(&mut record.title),
                username,
                password: record.password.take().unwrap_or_default(),
                site: record.site.take().unwrap_or_default(),
                notes: record.misc.take().unwrap_or_default(),
                group,
            }));
        }

        Ok(Self::Note(NoteRecord {
            title: std::mem::take(&mut record.title),
            text: record.misc.take().unwrap_or_default(),
            group,
        }))
    }
}

fn deserialize_optional_string<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod tests {
    use crate::{
        Error,
        payload::{DecodedPayload, NotesRecord},
    };

    #[test]
    fn decodes_quick_text_note() {
        let decoded =
            DecodedPayload::decode(br#"n[{"title":"Quick Note","misc":"Meet at the park"}]"#)
                .unwrap();
        let DecodedPayload::Notes(notes) = decoded else {
            panic!("expected notes payload");
        };
        let [NotesRecord::Note(note)] = notes.records() else {
            panic!("expected one secure note");
        };

        assert_eq!(note.title(), "Quick Note");
        assert_eq!(note.text(), "Meet at the park");
        assert_eq!(note.group(), "");
    }

    #[test]
    fn decodes_note_and_password_display_fields() {
        let decoded = DecodedPayload::decode(
            br#"n[
                {"title":"Recovery","misc":"stored offsite","group":"Bitcoin"},
                {"title":"Server","user":"alice","password":"correct horse","site":"example.com","misc":"rotate yearly","group":"Work"}
            ]"#,
        )
        .unwrap();
        let DecodedPayload::Notes(notes) = decoded else {
            panic!("expected notes payload");
        };
        let [NotesRecord::Note(note), NotesRecord::Password(password)] = notes.records() else {
            panic!("expected a note followed by a password");
        };

        assert_eq!(note.title(), "Recovery");
        assert_eq!(note.text(), "stored offsite");
        assert_eq!(note.group(), "Bitcoin");
        assert_eq!(password.title(), "Server");
        assert_eq!(password.username(), "alice");
        assert_eq!(password.password(), "correct horse");
        assert_eq!(password.site(), "example.com");
        assert_eq!(password.notes(), "rotate yearly");
        assert_eq!(password.group(), "Work");
    }

    #[test]
    fn password_record_uses_user_field_as_protocol_discriminator() {
        let decoded =
            DecodedPayload::decode(br#"n[{"title":"Empty password","user":""}]"#).unwrap();
        let DecodedPayload::Notes(notes) = decoded else {
            panic!("expected notes payload");
        };
        let [NotesRecord::Password(password)] = notes.records() else {
            panic!("expected one password record");
        };

        assert_eq!(password.username(), "");
        assert_eq!(password.password(), "");
    }

    #[test]
    fn rejects_malformed_notes_as_payload_errors() {
        let malformed = [
            &b"n\xff"[..],
            &b"nnot-json"[..],
            &b"n{}"[..],
            &b"n[]"[..],
            &br#"n[{"misc":"missing title"}]"#[..],
            &br#"n[{"title":""}]"#[..],
            &br#"n[{"title":"wrong type","misc":7}]"#[..],
            &br#"n[{"title":"null field","misc":null}]"#[..],
            &br#"n[{"title":"missing user","password":"secret"}]"#[..],
            &br#"n[{"title":"unknown field","other":"secret"}]"#[..],
        ];

        for payload in malformed {
            assert!(matches!(DecodedPayload::decode(payload), Err(Error::InvalidNotesPayload)));
        }
    }
}
