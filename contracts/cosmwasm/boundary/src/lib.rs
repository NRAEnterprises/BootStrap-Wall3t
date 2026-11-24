use cosmwasm_std::{to_json_binary, Binary, Deps, Env, MessageInfo, Response, StdResult};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ContractError {
    #[error("execution is intentionally unavailable in the boundary target")]
    ExecutionDisabled,
}

pub fn instantiate(_deps: Deps, _env: Env, _info: MessageInfo) -> StdResult<Response> {
    Ok(Response::new().add_attribute("protocol_version", "1"))
}

pub fn execute(
    _deps: Deps,
    _env: Env,
    _info: MessageInfo,
    _msg: Binary,
) -> Result<Response, ContractError> {
    Err(ContractError::ExecutionDisabled)
}

pub fn query(_deps: Deps, _env: Env, _msg: Binary) -> StdResult<Binary> {
    to_json_binary(&1u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::Addr;

    #[test]
    fn execution_is_disabled() {
        let deps = mock_dependencies();
        let sender = Addr::unchecked("test");
        let err = execute(deps.as_ref(), mock_env(), message_info(&sender, &[]), Binary::default())
            .expect_err("boundary must not execute value-moving actions");
        assert_eq!(err, ContractError::ExecutionDisabled);
    }
}
