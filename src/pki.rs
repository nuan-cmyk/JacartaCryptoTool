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

    /// Выполняет авторизованную операцию пользователя, перебирая все доступные слоты токена (Laser, Datastore, GOST).
    /// Это гарантирует выбор правильного апплета, даже если в системе доступно несколько слотов.
    pub fn with_user_session<T>(
        &self,
        user_pin: &str,
        action: impl Fn(&Session) -> Result<T, Box<dyn Error>>,
    ) -> Result<T, Box<dyn Error>> {
        let slots = self.pkcs11.get_slots_with_token()?;
        if slots.is_empty() {
            return Err("Токен не найден. Убедитесь, что JaCarta LT подключён.".into());
        }

        let mut errors = Vec::new();

        for slot in slots {
            let session = match self.pkcs11.open_rw_session(slot) {
                Ok(s) => s,
                Err(e) => {
                    errors.push(format!("Слот {:?}: Ошибка открытия сессии {:?}", slot, e));
                    continue;
                }
            };

            if let Err(e) = session.login(UserType::User, Some(&AuthPin::new(user_pin.into()))) {
                errors.push(format!("Слот {:?}: Ошибка авторизации ({:?})", slot, e));
                continue;
            }

            // Авторизация прошла успешно! Выполняем требуемую операцию
            let result = action(&session);
            let _ = session.logout();
            return result;
        }

        Err(format!("Не удалось авторизоваться ни на одном из слотов токена. Ошибки: {}", errors.join("; ")).into())
    }

    /// Смена User PIN.
    pub fn change_pin(&self, pin: &str, new_pin: &str, _is_admin: bool) -> Result<(), Box<dyn Error>> {
        self.with_user_session(pin, |session| {
            session.set_pin(&AuthPin::new(pin.into()), &AuthPin::new(new_pin.into()))?;
            Ok(())
        })
    }

    /// Получение или создание 256-битного мастер-ключа шифрования в защищённом хранилище Datastore на JaCarta LT.
    pub fn get_or_create_master_key(&self, user_pin: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        self.with_user_session(user_pin, |session| {
            let key_id = vec![0x4A, 0x43, 0x52, 0x01]; // "JCR\x01"

            let template = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Id(key_id.clone()),
            ];

            let objects = session.find_objects(&template)?;
            if !objects.is_empty() {
                // Ключ найден — считываем его
                let attrs = session.get_attributes(objects[0], &[AttributeType::Value])?;
                for attr in attrs {
                    if let Attribute::Value(val) = attr {
                        if val.len() == 32 {
                            return Ok(val);
                        }
                    }
                }
            }

            // Ключ еще не создан — генерируем новый случайный AES-256 ключ
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
