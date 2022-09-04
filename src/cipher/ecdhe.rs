use primit::rng::cprng::FastRng;
use rand::rngs::OsRng;
use std::io::Cursor;

use super::KeyExchange;
use crate::handshake::NamedCurve;
use crate::signature::DigitallySigned;
use crate::tls_item::TlsItem;
use crate::tls_result;
use crate::tls_result::TlsErrorKind::IllegalParameter;
use crate::tls_result::TlsResult;
use crate::util::{ReadExt, WriteExt};

tls_vec!(EcData = u8(1, (1 << 8) - 1));

tls_struct!(
    struct EcCurve {
        a: EcData,
        b: EcData,
    }
);

// usage:
// struct {
//     Type type;
//     "opaque" {
//         select (type) {
//             case TypeVariant1:
//                 ...
//             case TypeVariant2:
//                 ...
//         }
//     }
// } Struct;
macro_rules! tls_enum_struct {
    (
        $repr_ty:ident,
        $(#[$a:meta])*
        enum $enum_name:ident {
            $(
                $name:ident($body_ty:ident) = $num:tt$(,)* // $num: integer literal
            ),+
        }
    ) => (
        #[allow(non_camel_case_types)]
        $(#[$a])*
        pub enum $enum_name {
            $(
                $name($body_ty),
            )+
        }

        impl TlsItem for $enum_name {
            fn tls_write<W: WriteExt>(&self, writer: &mut W) -> crate::tls_result::TlsResult<()> {
                match *self {
                    $(
                        $enum_name::$name(ref body) => {
                            try_write_num!($repr_ty, writer, tt_to_expr!($num));
                            body.tls_write(writer)?;
                        }
                    )+
                }
                Ok(())
            }

            fn tls_read<R: ReadExt>(reader: &mut R) -> crate::tls_result::TlsResult<$enum_name> {
                let num = try_read_num!($repr_ty, reader);
                match num {
                    $(
                        tt_to_pat!($num) => {
                            let body: $body_ty = TlsItem::tls_read(reader)?;
                            Ok($enum_name::$name(body))
                        }
                    )+
                    _ => return tls_err!(tls_result::TlsErrorKind::DecodeError,
                                         "unexpected value: {}", num),
                }
            }

            fn tls_size(&self) -> u64 {
                let prefix_size = num_size!($repr_ty);
                let body_size = match *self {
                    $(
                        $enum_name::$name(ref body) => body.tls_size(),
                    )+
                };
                prefix_size + body_size
            }
        }
    )
}

tls_enum_struct!(
    u8,
    enum EcParameters {
        // explicit_prime(...) = 1,
        // explicit_char2(...) = 2,
        named_curve(NamedCurve) = 3,
    }
);

tls_struct!(
    struct ServerEcdhParams {
        curve_params: EcParameters,
        public: EcData,
    }
);

tls_struct!(
    struct EcdheServerKeyExchange {
        params: ServerEcdhParams,
        signed_params: DigitallySigned,
    }
);

pub struct EllipticDiffieHellman;

impl KeyExchange for EllipticDiffieHellman {
    fn compute_keys(&self, data: &[u8], _: &mut OsRng) -> TlsResult<(Vec<u8>, Vec<u8>)> {
        let mut reader = Cursor::new(data);
        let ecdh_params: EcdheServerKeyExchange = TlsItem::tls_read(&mut reader)?;

        use primit::ec::p256::P256;
        use primit::ec::ECDHE;

        let mut rng = FastRng::new_from_system();
        let sk = P256::new(&mut rng);

        let peer_pk: &[u8] = &ecdh_params.params.public;
        let gy = match sk.exchange(peer_pk.try_into().unwrap()) {
            Ok(shared_secret) => shared_secret,
            Err(_) => {
                return tls_err!(IllegalParameter, "server sent strange public key");
            }
        };

        // we don't support client cert. send public key explicitly.
        let public = EcData::new(sk.to_public().to_vec())?;

        let mut data = Vec::new();
        public.tls_write(&mut data)?;
        let public = data;

        Ok((public, gy.to_vec()))
    }
}
