use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};

fn main() {
    let dll_path = if cfg!(target_pointer_width = "64") {
        "drivers/jcPKCS11_2_Win64.dll"
    } else {
        "drivers/jcPKCS11_2_Win32.dll"
    };

    let pkcs11 = match Pkcs11::new(dll_path) {
        Ok(p) => p,
        Err(e) => {
            println!("Failed to load dll: {:?}", e);
            return;
        }
    };
    
    if let Err(e) = pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        println!("Initialize error: {:?}", e);
        return;
    }

    let slots = pkcs11.get_slots_with_token().unwrap_or_default();
    if slots.is_empty() {
        println!("No token found");
        return;
    }
    
    for slot in slots {
        println!("Slot: {:?}", slot);
        match pkcs11.get_mechanism_list(slot) {
            Ok(mechs) => {
                let mut found_aes = false;
                for mech in mechs {
                    let s = format!("{:?}", mech);
                    if s.contains("AES") || s.contains("Aes") || s.contains("aes") {
                        println!("Mechanism: {:?}", mech);
                        found_aes = true;
                    }
                }
                if !found_aes {
                    println!("No AES mechanisms supported by this token!");
                }
            }
            Err(e) => println!("Error getting mechs: {:?}", e),
        }
    }
}
