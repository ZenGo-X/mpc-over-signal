#![feature(drain_filter)]

use std::convert::{TryFrom, TryInto};

mod actors;
mod device;
mod helpers;
mod signal_client;
mod webapi;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/signalservice.rs"));
}

pub use device::{Device, DeviceStore};
use libsignal_protocol::ProtocolAddress;
pub use signal_client::{SignalClient, SignalClientBuilder, SignalClientConnected};

#[derive(Clone, Debug)]
pub struct Group {
    participants: Vec<ParticipantIdentity>,
}

impl Group {
    pub fn new(mut parties: Vec<ParticipantIdentity>) -> Self {
        parties.sort();
        Self {
            participants: parties,
        }
    }
    pub fn party_index(&self, party_addr: &libsignal_protocol::ProtocolAddress) -> Option<u16> {
        self.participants
            .iter()
            .enumerate()
            .find(|(_, p)| &p.addr == party_addr)
            .map(|(i, _)| u16::try_from(i + 1).ok())
            .flatten()
    }

    pub fn lookup_party_addr_by_index(&self, ind: u16) -> Option<&ProtocolAddress> {
        if ind == 0 {
            None
        } else {
            self.participants.get(usize::from(ind - 1)).map(|p| &p.addr)
        }
    }

    pub fn parties_count(&self) -> u16 {
        self.participants.len().try_into().unwrap()
    }

    pub fn parties(&self) -> impl Iterator<Item = &ParticipantIdentity> {
        self.participants.iter()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ParticipantIdentity {
    pub addr: libsignal_protocol::ProtocolAddress,
    pub public_key: libsignal_protocol::IdentityKey,
}
