#![warn(clippy::style, missing_debug_implementations)]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

extern crate alloc;

pub const CONTRACT_VERSION: &str = "0.1.0";

wit_bindgen::generate!({
    world: "oriel",
    path: "wit",
    additional_derives: [
        serde::Deserialize,
        serde::Serialize,
    ],
    generate_all,
});

mod contract;
mod engine;
mod model;

struct Component;

#[cfg(target_arch = "wasm32")]
impl exports::z::oriel::contracts::Guest for Component {
    fn run_qualification(
        req: exports::z::oriel::contracts::GenericInput,
    ) -> Result<Vec<u8>, String> {
        let input = req.input.ok_or("run-qualification: missing input")?;
        contract::run_qualification(&input)
    }

    fn get_qualification(
        req: exports::z::oriel::contracts::GenericInput,
    ) -> Result<Vec<u8>, String> {
        let input = req.input.ok_or("get-qualification: missing input")?;
        contract::get_qualification(&input)
    }

    fn protected_support_action(
        req: exports::z::oriel::contracts::GenericInput,
    ) -> Result<Vec<u8>, String> {
        let input = req.input.ok_or("protected-support-action: missing input")?;
        contract::protected_support_action(&input)
    }

    fn revoke_qualification(
        req: exports::z::oriel::contracts::GenericInput,
    ) -> Result<Vec<u8>, String> {
        let input = req.input.ok_or("revoke-qualification: missing input")?;
        contract::revoke_qualification(&input)
    }
}

#[cfg(target_arch = "wasm32")]
export!(Component);

#[cfg(test)]
mod tests {
    use super::CONTRACT_VERSION;

    #[test]
    fn contract_version_is_semver() {
        let parts: Vec<&str> = CONTRACT_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|part| part.parse::<u32>().is_ok()));
    }
}
