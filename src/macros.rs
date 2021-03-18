macro_rules! tls_err {
    ($kind:expr, $($args:tt)*) => (
        $crate::tls_result::TlsError::new($kind, format!($($args)*))
    )
}

macro_rules! num_size {
    (u8) => (1);
    (u16) => (2);
    (u24) => (3);
    (u32) => (4);
    (u64) => (8);
}

macro_rules! try_write_num {
    (u8, $writer:expr, $e:expr) => ({
        $writer.write_u8($e as u8)?;
    });
    (u16, $writer:expr, $e:expr) => ({
        $writer.write_be_u16($e as u16)?;
    });
    (u24, $writer:expr, $e:expr) => (
        {
            let e = $e as u32;
            $writer.write_u8((e >> 16) as u8)?;
            $writer.write_u8((e >> 8) as u8)?;
            $writer.write_u8(e as u8)?;
        }
    );
    (u32, $writer:expr, $e:expr) => ({
        $writer.write_be_u32($e as u32)?;
    });
    (u64, $writer:expr, $e:expr) => ({
        $writer.write_be_u64($e as u64)?;
    });
}

macro_rules! try_read_num {
    (u8, $reader:expr) => ({
        $reader.read_u8()?
    });
    (u16, $reader:expr) => ({
        $reader.read_be_u16()?
    });
    (u24, $reader:expr) => ({
        let n1 = $reader.read_u8()? as u32;
        let n2 = $reader.read_u8()? as u32;
        let n3 = $reader.read_u8()? as u32;
        (n1 << 16) | (n2 << 8) | n3
    });
    (u32, $reader:expr) => ({
        $reader.read_be_u32()?
    });
    (u64, $reader:expr) => ({
        $reader.read_be_u64()?
    });
}

macro_rules! tt_to_expr {
    ($num:expr) => ($num)
}
macro_rules! tt_to_pat {
    ($num:pat) => ($num)
}
