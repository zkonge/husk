use num::traits::FromPrimitive;
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::prelude::*;

use crate::cipher::{Decryptor, Encryptor};
use crate::handshake::{Handshake, HandshakeBuffer};
use crate::tls_item::TlsItem;
use crate::tls_result::TlsErrorKind::{
    AlertReceived, BadRecordMac, RecordOverflow, UnexpectedMessage,
};
use crate::tls_result::TlsResult;
use crate::util::{ReadExt, WriteExt};
use crate::{
    alert::{Alert, AlertDescription},
    util::u64_be_array,
};

use self::ContentType::{AlertTy, ApplicationDataTy, ChangeCipherSpecTy, HandshakeTy};
use self::Message::{
    AlertMessage, ApplicationDataMessage, ChangeCipherSpecMessage, HandshakeMessage,
};

pub static TLS_VERSION: (u8, u8) = (3, 3);

enum_from_primitive! {
    #[repr(u8)]
    #[derive(Copy, Clone, PartialEq, Debug)]
    pub enum ContentType {
        ChangeCipherSpecTy = 20,
        AlertTy = 21,
        HandshakeTy = 22,
        ApplicationDataTy = 23,
        // HeartBeat = 24, RFC 6520 extension :-)
    }
}

/// maximum length of Record (excluding content_type, version, length fields)
pub const RECORD_MAX_LEN: usize = 1 << 14;

/// maximum length of EncryptedRecord (excluding content_type, version, length fields)
pub const ENC_RECORD_MAX_LEN: usize = (1 << 14) + 2048;

/// corresponds to `TLSPlaintext` in Section 6.2.1.
#[derive(Debug)]
pub struct Record {
    pub content_type: ContentType,
    pub ver_major: u8,
    pub ver_minor: u8,
    // fragment length < 2^14
    pub fragment: Vec<u8>,
}

impl Record {
    pub fn new(
        content_type: ContentType,
        ver_major: u8,
        ver_minor: u8,
        fragment: Vec<u8>,
    ) -> Record {
        let len = fragment.len();
        if len > RECORD_MAX_LEN {
            panic!("record too long: {} > 2^14", len);
        }

        Record {
            content_type,
            ver_major,
            ver_minor,
            fragment,
        }
    }
}

/// Writes `Record` or higher-layer message to a writable object.
/// Record is internally encrypted before written.
pub struct TlsWriter<W: Write> {
    writer: W,
    // if encryptor is None, handshake is not done yet.
    encryptor: Option<Box<dyn Encryptor + Send + 'static>>,
    write_count: u64,
    iv: Option<Vec<u8>>,
}

impl<W: Write> TlsWriter<W> {
    /// Create new `TlsWriter` with null encryption.
    /// Invoke `set_encryptor` to set encryptor.
    pub fn new(writer: W) -> TlsWriter<W> {
        TlsWriter {
            writer,
            encryptor: None,
            write_count: 0,
            iv: None,
        }
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Set encryptor and reset count.
    /// This must be called only once.
    pub fn set_encryptor(&mut self, encryptor: Box<dyn Encryptor + Send + 'static>) {
        assert!(self.encryptor.is_none());
        self.encryptor = Some(encryptor);
        self.write_count = 0;
    }

    /// Set iv for aead.
    /// This must be called only once.
    pub fn set_iv(&mut self, iv: Vec<u8>) {
        assert!(self.iv.is_none());
        self.iv = Some(iv);
    }

    pub fn write_record(&mut self, record: Record) -> TlsResult<()> {
        let encrypted_fragment = match self.encryptor {
            None => record.fragment,
            Some(ref mut encryptor) => {
                let seq_num = u64_be_array(self.write_count);
                let mut u96_seq_num = [0u8; 12];
                u96_seq_num[4..12].copy_from_slice(&seq_num);

                let mut ad = Vec::new();
                ad.extend(&seq_num);
                ad.push(record.content_type as u8);
                ad.push(record.ver_major);
                ad.push(record.ver_minor);

                let frag_len = record.fragment.len() as u16;
                ad.push((frag_len >> 8) as u8);
                ad.push(frag_len as u8);

                let mut result_buf = vec![];
                if let Some(ref iv) = self.iv {
                    if iv.len() == 4 {
                        // aes-gcm
                        u96_seq_num[..4].copy_from_slice(&iv);
                        OsRng.fill_bytes(&mut u96_seq_num[4..]);
                        result_buf.extend_from_slice(&u96_seq_num[4..]);
                    } else if iv.len() == 12 {
                        // chacha20-poly1305
                        u96_seq_num
                            .iter_mut()
                            .zip(iv.iter())
                            .for_each(|(nonce, ivk)| *nonce ^= *ivk);
                    }
                }
                result_buf.append(&mut encryptor.encrypt(&u96_seq_num, &record.fragment, &ad));
                result_buf
            }
        };

        let fragment_len = encrypted_fragment.len();
        if fragment_len > ENC_RECORD_MAX_LEN {
            panic!("record too long: {} > 2^14 + 2048", fragment_len);
        }

        self.writer.write_u8(record.content_type as u8)?;
        self.writer.write_u8(record.ver_major)?;
        self.writer.write_u8(record.ver_minor)?;
        self.writer.write_be_u16(fragment_len as u16)?;
        self.writer.write_all(&encrypted_fragment)?;

        self.write_count += 1;

        Ok(())
    }

    pub fn write_data(&mut self, ty: ContentType, data: &[u8]) -> TlsResult<()> {
        let (major, minor) = TLS_VERSION;
        // TODO: configurable maxlen
        for fragment in data.chunks(RECORD_MAX_LEN) {
            let fragment = fragment.to_vec();
            let record = Record::new(ty, major, minor, fragment);
            self.write_record(record)?;
        }

        Ok(())
    }

    pub fn write_handshake(&mut self, handshake: &Handshake) -> TlsResult<()> {
        let mut data = Vec::new();
        handshake.tls_write(&mut data)?;
        self.write_data(HandshakeTy, &data)
    }

    pub fn write_alert(&mut self, alert: &Alert) -> TlsResult<()> {
        let mut data = Vec::new();
        alert.tls_write(&mut data)?;
        self.write_data(AlertTy, &data)
    }

    pub fn write_change_cipher_spec(&mut self) -> TlsResult<()> {
        self.write_data(ChangeCipherSpecTy, &[1u8])
    }

    pub fn write_application_data(&mut self, data: &[u8]) -> TlsResult<()> {
        if self.encryptor.is_none() {
            panic!("attempted to write ApplicationData before handshake");
        }
        self.write_data(ApplicationDataTy, data)
    }
}

/// Return type of `TlsReader.read_record()`.
pub enum Message {
    HandshakeMessage(Handshake),
    ChangeCipherSpecMessage,
    AlertMessage(Alert),
    ApplicationDataMessage(Vec<u8>),
}

pub struct TlsReader<R: ReadExt> {
    reader: R,
    // if decryptor is none, handshake is not done yet.
    decryptor: Option<Box<dyn Decryptor + Send + 'static>>,
    read_count: u64,
    handshake_buffer: HandshakeBuffer,
    iv: Option<Vec<u8>>,
}

/// Reads `Record` or `Message` from a readable object.
/// Record is internally decrypted after read.
impl<R: ReadExt> TlsReader<R> {
    pub fn new(reader: R) -> TlsReader<R> {
        TlsReader {
            reader,
            decryptor: None,
            read_count: 0,
            handshake_buffer: HandshakeBuffer::new(),
            iv: None,
        }
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Set decryptor and reset count.
    /// This must be called only once.
    pub fn set_decryptor(&mut self, decryptor: Box<dyn Decryptor + Send + 'static>) {
        assert!(self.decryptor.is_none());
        self.decryptor = Some(decryptor);
        self.read_count = 0;
    }

    /// Set iv for aead.
    /// This must be called only once.
    pub fn set_iv(&mut self, iv: Vec<u8>) {
        assert!(self.iv.is_none());
        self.iv = Some(iv);
    }

    /// Read a record from readable stream.
    ///
    /// Any record with unknown content type is treated as an error.
    fn read_record(&mut self) -> TlsResult<Record> {
        let content_type = {
            let ty = self.reader.read_u8()?;
            let ct: Option<ContentType> = FromPrimitive::from_u8(ty);
            match ct {
                Some(ty) => ty,
                None => return tls_err!(UnexpectedMessage, "unexpected ContentType: {}", ty),
            }
        };

        let major = self.reader.read_u8()?;
        let minor = self.reader.read_u8()?;

        let len = {
            let len = self.reader.read_be_u16()? as usize;
            if len > ENC_RECORD_MAX_LEN {
                return tls_err!(RecordOverflow, "TLSEncryptedText too long: {}", len);
            }
            len
        };

        let fragment = ReadExt::read_exact(&mut self.reader, len as usize)?;

        let record = match self.decryptor {
            None => {
                if fragment.len() > RECORD_MAX_LEN {
                    return tls_err!(
                        RecordOverflow,
                        "decrypted record too long: {}",
                        fragment.len()
                    );
                }
                Record::new(content_type, major, minor, fragment)
            }
            Some(ref mut decryptor) => {
                let seq_num = u64_be_array(self.read_count);
                let mut u96_seq_num = [0u8; 12];
                u96_seq_num[4..12].copy_from_slice(&seq_num);
                // let seq_num = u32_be_array(self.read_count);

                let mut ad = Vec::new();
                ad.extend(&seq_num);
                ad.push(content_type as u8); // TLSCompressed.type
                ad.push(major);
                ad.push(minor);

                let mac_len = decryptor.mac_len();
                let explicit_iv_len = decryptor.fixed_iv_len();
                let total_len = fragment.len();
                if total_len < mac_len + explicit_iv_len {
                    return tls_err!(BadRecordMac, "encrypted message too short: {}", total_len);
                }

                let frag_len = (total_len - mac_len - explicit_iv_len) as u16;
                ad.push((frag_len >> 8) as u8);
                ad.push(frag_len as u8);

                if let Some(ref iv) = self.iv {
                    if iv.len() == 4 {
                        // aes-gcm
                        u96_seq_num[..4].copy_from_slice(&iv);
                        u96_seq_num[4..].copy_from_slice(&fragment[..8]);
                    } else if iv.len() == 12 {
                        // chacha20-poly1305
                        u96_seq_num
                            .iter_mut()
                            .zip(iv.iter())
                            .for_each(|(nonce, ivk)| *nonce ^= *ivk);
                    }
                }

                // TODO: "seq_num as nonce" is chacha20poly1305-specific
                let data = decryptor.decrypt(&u96_seq_num, &fragment[explicit_iv_len..], &ad)?;
                if data.len() > RECORD_MAX_LEN {
                    // decryption routine went wrong.
                    panic!("decrypted record too long: {}", data.len());
                }

                Record::new(content_type, major, minor, data)
            }
        };

        self.read_count += 1;

        Ok(record)
    }

    /// Read records until a "complete" message is found, then return the message.
    ///
    /// if invalid ChangeCipherSpec/Alert/Handshake message is found, return Err.
    /// (application record is always considered "complete" and "valid"
    /// since it is opaque to TLS layer.)
    ///
    /// Note: In theory, `Alert` message can be broken into several records.
    /// It is not useful in practice and requires more complex routines.
    /// (Incorrect handling leads to [Alert attack](http://www.mitls.org/wsgi/alert-attack).)
    ///
    /// We treat partial alert message as an error and returns `UnexpectedMessage`.
    pub fn read_message(&mut self) -> TlsResult<Message> {
        if let Some(handshake_msg) = self.handshake_buffer.get_message()? {
            return Ok(HandshakeMessage(handshake_msg));
        }

        // ok, no message found. read it from network!
        loop {
            // TODO: what if handshake record is present in buffer then
            // other record comes? is it legal?

            let record = self.read_record()?;
            match record.content_type {
                ChangeCipherSpecTy => {
                    if record.fragment.len() != 1 || record.fragment[0] != 1 {
                        return tls_err!(UnexpectedMessage, "invalid ChangeCipherSpec arrived");
                    }
                    return Ok(ChangeCipherSpecMessage);
                }
                AlertTy => {
                    let len = record.fragment.len();
                    if len == 0 {
                        return tls_err!(UnexpectedMessage, "zero-length Alert record arrived");
                    } else if len < 2 {
                        // alert attack
                        return tls_err!(UnexpectedMessage, "awkward Alert record arrived");
                    }
                    let level = FromPrimitive::from_u8(record.fragment[0]);
                    let desc = FromPrimitive::from_u8(record.fragment[1]);
                    match (level, desc) {
                        (Some(level), Some(desc)) => {
                            return Ok(AlertMessage(Alert::new(level, desc)?));
                        }
                        _ => {
                            return tls_err!(
                                UnexpectedMessage,
                                "unknown alert: {:?}",
                                record.fragment
                            )
                        }
                    }
                }
                HandshakeTy => {
                    if record.fragment.is_empty() {
                        return tls_err!(UnexpectedMessage, "zero-length Handshake arrived");
                    }
                    self.handshake_buffer.add_record(&record.fragment);

                    if let Some(handshake_msg) = self.handshake_buffer.get_message()? {
                        return Ok(HandshakeMessage(handshake_msg));
                    }
                }
                ApplicationDataTy => {
                    return Ok(ApplicationDataMessage(record.fragment));
                }
            }
        }
    }

    pub fn read_application_data(&mut self) -> TlsResult<Vec<u8>> {
        if self.decryptor.is_none() {
            panic!("ApplicationData called before handshake");
        }
        loop {
            let msg = self.read_message()?;
            match msg {
                ApplicationDataMessage(msg) => return Ok(msg),
                // TODO: handle other cases
                AlertMessage(Alert {
                    level: _,
                    description: AlertDescription::close_notify,
                }) => return Ok(vec![]),
                AlertMessage(..) => unimplemented!(),
                ChangeCipherSpecMessage => unimplemented!(), // this should not come here
                HandshakeMessage(..) => unimplemented!(),    // TODO: re-handshake
            }
        }
    }

    pub fn read_handshake(&mut self) -> TlsResult<Handshake> {
        match self.read_message()? {
            HandshakeMessage(handshake) => Ok(handshake),
            AlertMessage(alert) => tls_err!(AlertReceived, "alert: {:?}", alert.description),
            _ => tls_err!(UnexpectedMessage, "expected Handshake"),
        }
    }

    pub fn read_change_cipher_spec(&mut self) -> TlsResult<()> {
        match self.read_message()? {
            ChangeCipherSpecMessage => Ok(()),
            AlertMessage(..) => {
                tls_err!(UnexpectedMessage, "expected ChangeCipherSpec, get alert")
            }
            _ => tls_err!(UnexpectedMessage, "expected ChangeCipherSpec"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cipher::Encryptor;
    use crate::tls_result;
    use std::io::Cursor;

    macro_rules! assert_record {
        ($a:expr, $b:expr) => {
            assert_eq!($a.content_type, $b.content_type);
            assert_eq!($a.ver_major, $b.ver_major);
            assert_eq!($a.ver_minor, $b.ver_minor);
            assert_eq!($a.fragment, $b.fragment);
        };
    }

    fn new_reader(data: &[u8]) -> TlsReader<Cursor<&[u8]>> {
        TlsReader::new(Cursor::new(data))
    }

    macro_rules! assert_err {
        ($e:expr, $kind:ident) => {
            if let Err(e) = $e {
                assert_eq!(e.kind, tls_result::TlsErrorKind::$kind);
            } else {
                panic!("expected `Err`, found `Ok(..)`");
            }
        };
    }

    #[test]
    fn test_reader() {
        let tests: &[(&[u8], Record)] = &[
            // ChangeCipherSpec(1)
            (
                &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01],
                Record::new(ContentType::ChangeCipherSpecTy, 3, 3, vec![1]),
            ),
        ];
        for &(input, ref output) in tests {
            let mut rr = new_reader(input);
            let record = rr.read_record().unwrap();
            assert_record!(record, *output);
            let eof = rr.read_record();
            assert_err!(eof, IoFailure);
        }
    }

    #[test]
    fn test_reader_unknown() {
        // Heartbeat request
        let data = [0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x00, 0x20];
        let mut rr = new_reader(&data);
        let record = rr.read_record();
        assert_err!(record, UnexpectedMessage);
    }

    #[test]
    fn test_reader_too_long() {
        let len = RECORD_MAX_LEN + 1;
        let mut data = vec![0x17, 0x03, 0x03, (len >> 8) as u8, len as u8];
        for _ in 0..len {
            data.push(0xFF);
        }

        let mut rr = new_reader(&data);
        let record = rr.read_record();
        assert_err!(record, RecordOverflow);
    }

    #[test]
    fn test_reader_zero_length() {
        for content_type in vec![20, 21, 22] {
            let buf = [content_type, 0x03, 0x03, 0x00, 0x00];
            let mut rr = new_reader(&buf);
            let record = rr.read_message();
            assert_err!(record, UnexpectedMessage);
        }
    }

    #[test]
    #[should_panic]
    fn test_writer_too_long() {
        // convert normal record into overlong encrypted record
        struct Enc;
        impl Encryptor for Enc {
            fn encrypt(&mut self, _nonce: &[u8], _fragment: &[u8], _ad: &[u8]) -> Vec<u8> {
                vec![0; ENC_RECORD_MAX_LEN + 1]
            }
            fn fixed_iv_len(&self) -> usize {
                0
            }
        }

        let record = Record::new(ContentType::ApplicationDataTy, 3, 3, vec![1]);

        let mut rw = TlsWriter::new(Vec::new());
        rw.set_encryptor(Box::new(Enc) as Box<dyn Encryptor + Send>);
        let _unreachable = rw.write_record(record);
    }
}
