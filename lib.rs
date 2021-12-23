#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract]
mod aes_256_gcm_demo {

    use aes_gcm::aead::{Aead, NewAead};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    pub const IV_BYTES: usize = 12;
    pub type IV = [u8; IV_BYTES];

    pub const AES_KEY_BYTES: usize = 32;
    pub type AESKey = [u8; AES_KEY_BYTES];

    pub const BLOCK_BYTES: usize = 16;

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct Aes256GcmDemo {
        /// Stores a single `bool` value on the storage.
        value: bool,
    }

    impl Aes256GcmDemo {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(init_value: bool) -> Self {
            Self { value: init_value }
        }

        /// Constructor that initializes the `bool` value to `false`.
        ///
        /// Constructors can delegate to other constructors.
        #[ink(constructor)]
        pub fn default() -> Self {
            Self::new(Default::default())
        }

        /// A message that can be called on instantiated contracts.
        /// This one flips the value of the stored `bool` from `true`
        /// to `false` and vice versa.
        #[ink(message)]
        pub fn flip(&mut self) {
            self.value = !self.value;
        }

        /// Simply returns the current value of our `bool`.
        #[ink(message)]
        pub fn get(&self) -> bool {
            self.value
        }

        #[ink(message)]
        pub fn encrypt(&self, offset_bytes: u64, data: Vec<u8>, iv: IV, key: AESKey) -> Vec<u8> {
            if offset_bytes % (BLOCK_BYTES as u64) != 0 {
                panic!(
                    "Offset must be in multiples of block length of {} bytes",
                    BLOCK_BYTES
                );
            }

            let key = Key::from_slice(&key);
            let cipher = Aes256Gcm::new(key);
            // TODO: increase IV by offset / BLOCK_LEN
            let nonce = Nonce::from_slice(&iv); // 96-bits; unique per message

            cipher
                .encrypt(nonce, data.as_ref())
                .expect("encryption failure!")
        }

        #[ink(message)]
        pub fn decrypt(&self, offset_bytes: u64, data: Vec<u8>, iv: IV, key: AESKey) -> Vec<u8> {
            if offset_bytes % (BLOCK_BYTES as u64) != 0 {
                panic!(
                    "Offset must be in multiples of block length of {} bytes",
                    BLOCK_BYTES
                );
            }

            let key = Key::from_slice(&key);
            let cipher = Aes256Gcm::new(key);
            // TODO: increase IV by offset / BLOCK_LEN
            let nonce = Nonce::from_slice(&iv); // 96-bits; unique per message

            cipher
                .decrypt(nonce, data.as_ref())
                .expect("decryption failure!")
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// Imports `ink_lang` so we can use `#[ink::test]`.
        use ink_lang as ink;

        /// We test if the default constructor does its job.
        #[ink::test]
        fn default_works() {
            let aes_256_gcm_demo = Aes256GcmDemo::default();
            assert_eq!(aes_256_gcm_demo.get(), false);
        }

        /// We test a simple use case of our contract.
        #[ink::test]
        fn it_works() {
            let mut aes_256_gcm_demo = Aes256GcmDemo::new(false);
            assert_eq!(aes_256_gcm_demo.get(), false);
            aes_256_gcm_demo.flip();
            assert_eq!(aes_256_gcm_demo.get(), true);
        }

        #[ink::test]
        fn encrypt_and_decrypt() {
            let aes_256_gcm_demo = Aes256GcmDemo::default();

            let key: AESKey = [0; AES_KEY_BYTES];
            let iv: IV = [0; IV_BYTES];
            let data = b"plaintext message";

            let ciphertext = aes_256_gcm_demo.encrypt(0, data.to_vec(), iv, key);
            let plaintext = aes_256_gcm_demo.decrypt(0, ciphertext, iv, key);
            assert_eq!(plaintext, data.to_vec());
        }
    }
}
