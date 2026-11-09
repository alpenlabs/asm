export RUST_LOG=${RUST_LOG:-debug,sled=info,hyper=warn,soketto=warn,jsonrpsee-server=warn,mio=warn,bitcoind-async-client::client=warn,trie=warn}
export NO_COLOR=${NO_COLOR:-1}
export RUST_BACKTRACE=${RUST_BACKTRACE:-1}
export LOG_LEVEL=${LOG_LEVEL:-info}
# The params file whose spec_v2 section the SP1 guest bakes in. The envs start the runner with the
# same runtime part, so native and guest execution agree. A relative path is taken from the repo
# root. The guest build and the envs read the file from different directories, so it is exported
# as an absolute path.
ASM_PARAMS_PATH=${ASM_PARAMS_PATH:-crates/params/envs/dev.json}
if [[ "$ASM_PARAMS_PATH" != /* ]]; then
  ASM_PARAMS_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/$ASM_PARAMS_PATH"
fi
export ASM_PARAMS_PATH
