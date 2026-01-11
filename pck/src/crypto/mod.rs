//! AES-256-CFB encryption/decryption support for Godot 4 encrypted PCK files.
//!
//! Godot 4 uses AES-256-CFB mode for encrypting PCK files.
//! Each encrypted block has a 40-byte header: MD5(16) + original_size(8) + IV(16)

mod block;
mod key;
mod stream;
pub use block::{
    align_to_16, compute_md5, decrypt_cfb, encrypt_block, encrypt_cfb, generate_iv, verify_md5,
    EncryptedHeader, ENCRYPTED_HEADER_SIZE,
};

pub use key::parse_hex_key;

pub use stream::StreamingDecryptor;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_to_16() {
        assert_eq!(align_to_16(0), 0);
        assert_eq!(align_to_16(1), 16);
        assert_eq!(align_to_16(15), 16);
        assert_eq!(align_to_16(16), 16);
        assert_eq!(align_to_16(17), 32);
        assert_eq!(align_to_16(100), 112);
    }

    #[test]
    fn test_parse_hex_key() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = parse_hex_key(hex).unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[1], 0x23);
        assert_eq!(key[15], 0xef);
        assert_eq!(key[31], 0xef);
    }

    #[test]
    fn test_parse_hex_key_invalid_length() {
        let result = parse_hex_key("0123");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_header_parse() {
        let mut data = [0u8; 40];
        data[0..16].fill(0x11);
        data[16..24].copy_from_slice(&256i64.to_le_bytes());
        data[24..40].fill(0x22);

        let header = EncryptedHeader::parse(&data).unwrap();
        assert_eq!(header.md5, [0x11; 16]);
        assert_eq!(header.original_size, 256);
        assert_eq!(header.iv, [0x22; 16]);
    }
}
