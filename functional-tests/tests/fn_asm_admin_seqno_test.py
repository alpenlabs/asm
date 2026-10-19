import flexitest

from envs.basic_env import ADMIN_SECRET_KEY
from envs.upgrade_env import NATIVE_TEST_ASM_V1_PREDICATE
from rpc.client import RpcError
from utils.test_cli import submit_asm_stf_update
from utils.utils import (
    wait_until_asm_reaches_height,
    wait_until_asm_ready,
    wait_until_bitcoind_ready,
)


@flexitest.register
class AsmAdminSeqNoTest(flexitest.Test):
    """Query per-authority counters at historical blocks, with proving disabled."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        bitcoin_service = ctx.get_service("bitcoin")
        bitcoin_rpc = bitcoin_service.create_rpc()
        asm_rpc = ctx.get_service("asm_rpc").create_rpc()
        wait_until_bitcoind_ready(bitcoin_rpc, timeout=30)
        wait_until_asm_ready(asm_rpc)

        height = bitcoin_rpc.proxy.getblockcount()
        wallet_addr = bitcoin_rpc.proxy.getnewaddress()
        [initial_hash] = bitcoin_rpc.proxy.generatetoaddress(1, wallet_addr)
        wait_until_asm_reaches_height(asm_rpc, min_height=height + 1)
        roles = [
            "StrataAdministrator",
            "StrataSequencerManager",
            "AlpenAdministrator",
            "StrataSecurityCouncil",
        ]
        for role in roles:
            assert asm_rpc.strata_asm_getAdminSeqNo(initial_hash, role) == 0

        # Known Bitcoin history below the ASM anchor has no stored ASM state.
        genesis_hash = bitcoin_rpc.proxy.getblockhash(0)
        assert asm_rpc.strata_asm_getAdminSeqNo(genesis_hash, roles[0]) is None
        for args in [
            (),
            (initial_hash,),
            (None, roles[0]),
            ("invalid-hash", roles[0]),
            (initial_hash, None),
            (initial_hash, "UnknownAuthority"),
        ]:
            try:
                asm_rpc.strata_asm_getAdminSeqNo(*args)
            except RpcError as error:
                assert error.code == -32602
            else:
                raise AssertionError(f"getAdminSeqNo accepted invalid parameters: {args}")

        # The counter advances upon acceptance, before the queued update activates.
        txid = submit_asm_stf_update(
            bitcoin_service,
            admin_secret_key=ADMIN_SECRET_KEY,
            seqno=2,
            predicate=NATIVE_TEST_ASM_V1_PREDICATE,
        )
        [updated_hash] = bitcoin_rpc.proxy.generatetoaddress(1, wallet_addr)
        assert txid in bitcoin_rpc.proxy.getblock(updated_hash)["tx"]
        wait_until_asm_reaches_height(asm_rpc, min_height=height + 2)
        assert asm_rpc.strata_asm_getAdminSeqNo(updated_hash, roles[0]) == 2
        for role in roles[1:]:
            assert asm_rpc.strata_asm_getAdminSeqNo(updated_hash, role) == 0
        for role in roles:
            assert asm_rpc.strata_asm_getAdminSeqNo(initial_hash, role) == 0
        return True
