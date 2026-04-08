use std::str::FromStr;

use age_core::secrecy::zeroize::Zeroize;
use dialoguer::Password;
use getrandom::{rand_core::UnwrapErr, SysRng};
use rand::rngs::OsRng;
use rand::Rng;
use x509_cert::{
    der::{asn1::OctetString, referenced::OwnedToRef},
    ext::Extension,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoRef,
    time::Validity,
};
use yubikey::{
    certificate::Certificate,
    piv::{generate as yubikey_generate, AlgorithmId, RetiredSlotId, SlotId},
    Key, PinPolicy, TouchPolicy, YubiKey,
};

use crate::{
    error::Error,
    fl,
    key::{self, Stub},
    native::{mlkem768p256tag, p256tag},
    util::{Metadata, POLICY_EXTENSION_OID},
    Recipient, BINARY_NAME, USABLE_SLOTS,
};

pub(crate) const DEFAULT_IDENTITY_TYPE: IdentityType = IdentityType::TagPq;
pub(crate) const DEFAULT_PIN_POLICY: PinPolicy = PinPolicy::Once;
pub(crate) const DEFAULT_TOUCH_POLICY: TouchPolicy = TouchPolicy::Always;

pub(crate) struct IdentityBuilder {
    identity_type: Option<IdentityType>,
    slot: Option<RetiredSlotId>,
    force: bool,
    name: Option<String>,
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
}

impl IdentityBuilder {
    pub(crate) fn new(identity_type: Option<IdentityType>, slot: Option<RetiredSlotId>) -> Self {
        IdentityBuilder {
            identity_type,
            slot,
            name: None,
            pin_policy: None,
            touch_policy: None,
            force: false,
        }
    }

    pub(crate) fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    pub(crate) fn with_pin_policy(mut self, pin_policy: Option<PinPolicy>) -> Self {
        self.pin_policy = pin_policy;
        self
    }

    pub(crate) fn with_touch_policy(mut self, touch_policy: Option<TouchPolicy>) -> Self {
        self.touch_policy = touch_policy;
        self
    }

    pub(crate) fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub(crate) fn build(self, yubikey: &mut YubiKey) -> Result<(Stub, Recipient, Metadata), Error> {
        let identity_type = self.identity_type.unwrap_or(DEFAULT_IDENTITY_TYPE);

        let slot = match self.slot {
            Some(slot) => {
                if !self.force {
                    // Check that the slot is empty.
                    if Key::list(yubikey)?
                        .into_iter()
                        .any(|key| key.slot() == SlotId::Retired(slot))
                    {
                        return Err(Error::SlotIsNotEmpty(slot));
                    }
                }

                // Now either the slot is empty, or --force is specified.
                slot
            }
            None => {
                // Use the first empty slot.
                let keys = Key::list(yubikey)?;
                USABLE_SLOTS
                    .iter()
                    .find(|&&slot| !keys.iter().any(|key| key.slot() == SlotId::Retired(slot)))
                    .cloned()
                    .ok_or_else(|| Error::NoEmptySlots(yubikey.serial()))?
            }
        };

        let pin_policy = self.pin_policy.unwrap_or(DEFAULT_PIN_POLICY);
        let touch_policy = self.touch_policy.unwrap_or(DEFAULT_TOUCH_POLICY);

        eprintln!("{}", fl!("builder-gen-key"));

        // No need to ask for users to enter their PIN if the PIN policy requires it,
        // because here we _always_ require them to enter their PIN in order to access the
        // protected management key (which is necessary in order to generate identities).
        key::manage(yubikey)?;

        // Generate a new key in the selected slot.
        let generated = yubikey_generate(
            yubikey,
            SlotId::Retired(slot),
            identity_type.algorithm(),
            pin_policy,
            touch_policy,
        )?;

        let (pending_identity, recipient) = identity_type.recipient(generated.owned_to_ref())?;
        let stub = Stub::new(yubikey.serial(), slot, &recipient);

        eprintln!();
        eprintln!("{}", fl!("builder-gen-cert"));

        // Pick a random serial for the new self-signed certificate.
        let serial = SerialNumber::generate(&mut UnwrapErr(SysRng));

        let name = self
            .name
            .unwrap_or(format!("age identity {}", hex::encode(stub.tag)));

        if let PinPolicy::Always = pin_policy {
            // We need to enter the PIN again.
            let pin = Password::new()
                .with_prompt(fl!(
                    "plugin-enter-pin",
                    yubikey_serial = yubikey.serial().to_string(),
                ))
                .report(true)
                .interact()?;
            yubikey.verify_pin(pin.as_bytes())?;
        }
        if let TouchPolicy::Never = touch_policy {
            // No need to touch YubiKey
        } else {
            eprintln!("{}", fl!("builder-touch-yk"));
        }

        let policy_extension = Extension {
            extn_id: POLICY_EXTENSION_OID,
            critical: false,
            extn_value: OctetString::new(vec![pin_policy.into(), touch_policy.into()])
                .expect("valid"),
        };

        let extensions = pending_identity.generate_certificate(policy_extension);

        // TODO: https://github.com/iqlusioninc/yubikey.rs/issues/581
        let cert = Certificate::generate_self_signed::<_, p256_v0_14::NistP256>(
            yubikey,
            SlotId::Retired(slot),
            serial,
            // The original certificate never expired; preserve that behaviour.
            Validity::infinity().map_err(Error::Build)?,
            // TODO: https://github.com/RustCrypto/formats/issues/1489
            format!("O={BINARY_NAME},OU={},CN={name}", env!("CARGO_PKG_VERSION"))
                .parse()
                .map_err(Error::Build)?,
            generated,
            // TODO: https://github.com/iqlusioninc/yubikey.rs/issues/580
            |builder| {
                for ext in extensions {
                    builder.add_extension(ext)?;
                }
                Ok(())
            },
        )?;

        let metadata = Metadata::extract(yubikey, slot, &cert, false).unwrap();

        Ok((stub, recipient, metadata))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityType {
    Tag,
    TagPq,
}

impl FromStr for IdentityType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tag" => Ok(Self::Tag),
            "tagpq" => Ok(Self::TagPq),
            _ => Err(Error::InvalidIdentityType(s.into())),
        }
    }
}

impl ToString for IdentityType {
    fn to_string(&self) -> String {
        match self {
            IdentityType::Tag => "tag".into(),
            IdentityType::TagPq => "tagpq".into(),
        }
    }
}

impl IdentityType {
    fn algorithm(self) -> AlgorithmId {
        match self {
            Self::Tag | Self::TagPq { .. } => AlgorithmId::EccP256,
        }
    }

    fn recipient(self, spki: SubjectPublicKeyInfoRef<'_>) -> Result<(PendingIdentity, Recipient), Error> {
        match self {
            Self::Tag => Ok((
                PendingIdentity::Tag,
                Recipient::P256Tag(
                    p256tag::Recipient::from_spki(spki).expect("YubiKey generates a valid pubkey"),
                ),
            )),

            Self::TagPq => {
                // Generate the PQ half of the identity.
                let mut dk_seed = [0; 64];
                OsRng.fill(&mut dk_seed);
                let (_, ek_pq) = mlkem768p256tag::expand_pq_key(&dk_seed);

                Ok((
                    PendingIdentity::TagPq { dk_seed },
                    Recipient::MlKem768P256Tag(Box::new(
                        mlkem768p256tag::Recipient::from_spki(spki, ek_pq)
                            .expect("YubiKey generates a valid pubkey"),
                    )),
                ))
            }
        }
    }
}

enum PendingIdentity {
    Tag,
    TagPq { dk_seed: [u8; 64] },
}

impl PendingIdentity {
    fn generate_certificate(self, policy_extension: Extension) -> Vec<Extension> {
        match self {
            Self::Tag => vec![policy_extension],

            Self::TagPq { mut dk_seed } => {
                let exts = mlkem768p256tag::encode_ml_kem_768_seed(&dk_seed, |pq_ext| {
                    vec![pq_ext, policy_extension]
                });

                dk_seed.zeroize();

                exts
            }
        }
    }
}
