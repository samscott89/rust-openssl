use libc::*;

use *;

pub enum PKCS7_SIGNED {}
pub enum PKCS7_ENVELOPE {}
pub enum PKCS7_SIGN_ENVELOPE {}
pub enum PKCS7_DIGEST {}
pub enum PKCS7_ENCRYPT {}

#[repr(C)]
pub union pkcs7_st__d {
    pub ptr: *mut c_char,
    pub data: *mut ::ASN1_OCTET_STRING,
    pub sign: *mut ::PKCS7_SIGNED,
    pub enveloped: *mut ::PKCS7_ENVELOPE,
    pub signed_and_enveloped: *mut ::PKCS7_SIGN_ENVELOPE,
    pub digest: *mut ::PKCS7_DIGEST,
    pub encrypted: *mut ::PKCS7_ENCRYPT,
    pub other: *mut ::ASN1_TYPE,
}

#[repr(C)]
pub struct pkcs7_st {
    pub asn1: *mut c_uchar,
    pub length: c_long,
    pub state: c_int,
    pub detached: c_int,
    pub type_: *mut ::ASN1_OBJECT,
    pub d: pkcs7_st__d,
}

pub const PKCS7_TEXT: c_int = 0x1;
pub const PKCS7_NOCERTS: c_int = 0x2;
pub const PKCS7_NOSIGS: c_int = 0x4;
pub const PKCS7_NOCHAIN: c_int = 0x8;
pub const PKCS7_NOINTERN: c_int = 0x10;
pub const PKCS7_NOVERIFY: c_int = 0x20;
pub const PKCS7_DETACHED: c_int = 0x40;
pub const PKCS7_BINARY: c_int = 0x80;
pub const PKCS7_NOATTR: c_int = 0x100;
pub const PKCS7_NOSMIMECAP: c_int = 0x200;
pub const PKCS7_NOOLDMIMETYPE: c_int = 0x400;
pub const PKCS7_CRLFEOL: c_int = 0x800;
pub const PKCS7_STREAM: c_int = 0x1000;
pub const PKCS7_NOCRL: c_int = 0x2000;
pub const PKCS7_PARTIAL: c_int = 0x4000;
pub const PKCS7_REUSE_DIGEST: c_int = 0x8000;
#[cfg(not(any(ossl101, ossl102, libressl)))]
pub const PKCS7_NO_DUAL_CONTENT: c_int = 0x10000;

extern "C" {
    pub fn PKCS7_encrypt(
        certs: *mut stack_st_X509,
        b: *mut BIO,
        cipher: *const EVP_CIPHER,
        flags: c_int,
    ) -> *mut pkcs7_st;

    pub fn PKCS7_verify(
        pkcs7: *mut pkcs7_st,
        certs: *mut stack_st_X509,
        store: *mut X509_STORE,
        indata: *mut BIO,
        out: *mut BIO,
        flags: c_int,
    ) -> c_int;

    pub fn PKCS7_sign(
        signcert: *mut X509,
        pkey: *mut EVP_PKEY,
        certs: *mut stack_st_X509,
        data: *mut BIO,
        flags: c_int,
    ) -> *mut pkcs7_st;

    pub fn PKCS7_decrypt(
        pkcs7: *mut pkcs7_st,
        pkey: *mut EVP_PKEY,
        cert: *mut X509,
        data: *mut BIO,
        flags: c_int,
    ) -> c_int;

    pub fn SMIME_write_PKCS7(
        out: *mut BIO,
        pkcs7: *mut pkcs7_st,
        data: *mut BIO,
        flags: c_int,
    ) -> c_int;

    pub fn SMIME_read_PKCS7(bio: *mut BIO, bcont: *mut *mut BIO) -> *mut pkcs7_st;
}