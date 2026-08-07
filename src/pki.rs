use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::error::Error;

pub struct JacartaToken {
    pkcs11: Pkcs11,
}

impl JacartaToken {
    pub fn new(dll_path: &str) -> Result<Self, Box<dyn Error>> {
        let pkcs11 = Pkcs11::new(dll_path)?;
        pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
        Ok(Self { pkcs11 })
    }

    /// Performs an authorized user operation by iterating through all available token slots (Laser, Datastore, GOST).
    /// This ensures the correct applet is selected, even if multiple slots are available in the system.
    pub fn with_user_session<T>(
        &self,
        user_pin: &str,
        action: impl Fn(&Session) -> Result<T, Box<dyn Error>>,
    ) -> Result<T, Box<dyn Error>> {
        let slots = self.pkcs11.get_slots_with_token()?;
        if slots.is_empty() {
            return Err("Token not found. Ensure the JaCarta LT is connected.".into());
        }

        let mut errors = Vec::new();

        for slot in slots {
            let session = match self.pkcs11.open_rw_session(slot) {
                Ok(s) => s,
                Err(e) => {
                    errors.push(format!("Slot {:?}: Error opening session {:?}", slot, e));
                    continue;
                }
            };

            if let Err(e) = session.login(UserType::User, Some(&AuthPin::new(user_pin.into()))) {
                errors.push(format!("Slot {:?}: Authorization error ({:?})", slot, e));
                continue;
            }

            // Authorization successful! Performing the requested operation
            let result = action(&session);
            let _ = session.logout();
            return result;
        }

        Err(format!("Failed to authorize on any token slot. Errors: {}", errors.join("; ")).into())
    }

    /// Change User PIN.
    pub fn change_pin(&self, pin: &str, new_pin: &str, _is_admin: bool) -> Result<(), Box<dyn Error>> {
        self.with_user_session(pin, |session| {
            session.set_pin(&AuthPin::new(pin.into()), &AuthPin::new(new_pin.into()))?;
            Ok(())
        })
    }

    /// Retrieving or creating a 256-bit encryption master key in the secure Datastore on JaCarta LT.
    pub fn get_or_create_master_key(&self, user_pin: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        self.with_user_session(user_pin, |session| {
            let key_id = vec![0x4A, 0x43, 0x52, 0x01]; // "JCR\x01"

            let template = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Id(key_id.clone()),
            ];

            let objects = session.find_objects(&template)?;
            if !objects.is_empty() {
                // Key found - reading it
                let attrs = session.get_attributes(objects[0], &[AttributeType::Value])?;
                for attr in attrs {
                    if let Attribute::Value(val) = attr {
                        if val.len() == 32 {
                            return Ok(val);
                        }
                    }
                }
            }

            // Key not created yet - generating a new random AES-256 key
            let mut master_key = [0u8; 32];
            rand::fill(&mut master_key);

            let data_template = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Id(key_id),
                Attribute::Label("JaCarta Master Key".into()),
                Attribute::Value(master_key.to_vec()),
            ];

            session.create_object(&data_template)?;

            Ok(master_key.to_vec())
        })
    }
}

impl Drop for JacartaToken {
    fn drop(&mut self) {
        let _ = self.pkcs11.clone().finalize();
    }
}
