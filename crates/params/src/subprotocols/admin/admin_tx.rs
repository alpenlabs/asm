use std::fmt;

use crate::subprotocols::admin::updates::UpdateTxType;

/// Administration subprotocol transaction types.
/// by [`UpdateTxType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdminTxType {
    /// Cancel a previously queued update.
    Cancel,
    /// Propose an update of the kind described by [`UpdateTxType`].
    Update(UpdateTxType),
}

/// On-the-wire SPS-50 byte value for [`AdminTxType::Cancel`].
const CANCEL_TX_TYPE: u8 = 0;

impl From<UpdateTxType> for u8 {
    fn from(tx_type: UpdateTxType) -> Self {
        tx_type as u8
    }
}

impl From<UpdateTxType> for AdminTxType {
    fn from(tx_type: UpdateTxType) -> Self {
        AdminTxType::Update(tx_type)
    }
}

impl TryFrom<AdminTxType> for UpdateTxType {
    type Error = AdminTxType;

    fn try_from(tx_type: AdminTxType) -> Result<Self, Self::Error> {
        match tx_type {
            AdminTxType::Update(u) => Ok(u),
            AdminTxType::Cancel => Err(tx_type),
        }
    }
}

impl From<AdminTxType> for u8 {
    fn from(tx_type: AdminTxType) -> Self {
        match tx_type {
            AdminTxType::Cancel => CANCEL_TX_TYPE,
            AdminTxType::Update(u) => u.into(),
        }
    }
}

impl TryFrom<u8> for AdminTxType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            CANCEL_TX_TYPE => Ok(AdminTxType::Cancel),
            other => UpdateTxType::try_from(other).map(AdminTxType::Update),
        }
    }
}

impl fmt::Display for AdminTxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminTxType::Cancel => write!(f, "Cancel"),
            AdminTxType::Update(u) => u.fmt(f),
        }
    }
}
