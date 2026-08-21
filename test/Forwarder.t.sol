// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {Forwarder} from "../src/Forwarder.sol";
import {SampleRecipient} from "../src/SampleRecipient.sol";
import {ERC1271Wallet, GasBurner, ReentrantRecipient} from "./mocks/Mocks.sol";

contract ForwarderTest is Test {
    Forwarder internal forwarder;
    SampleRecipient internal recipient;

    address internal relayer = makeAddr("relayer");
    address internal alice;
    uint256 internal aliceKey;
    address internal bob;
    uint256 internal bobKey;

    bytes internal constant PAYLOAD = "hello world";

    function setUp() public {
        forwarder = new Forwarder("Forwarder");
        recipient = new SampleRecipient(address(forwarder));
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");
    }

    // --------------------------------------------------------------------- //
    //                               Helpers                                 //
    // --------------------------------------------------------------------- //

    function _pingData() internal pure returns (bytes memory) {
        return abi.encodeCall(SampleRecipient.ping, (PAYLOAD));
    }

    function _req(address from, address to, uint256 value, bytes memory data)
        internal
        view
        returns (Forwarder.ForwardRequest memory)
    {
        return Forwarder.ForwardRequest({
            from: from,
            to: to,
            value: value,
            gas: 500_000,
            nonce: forwarder.nonces(from),
            deadline: uint48(block.timestamp + 1 hours),
            data: data
        });
    }

    function _sign(uint256 key, Forwarder.ForwardRequest memory req) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, forwarder.hashRequest(req));
        return abi.encodePacked(r, s, v);
    }

    // --------------------------------------------------------------------- //
    //                          Happy path & verify                          //
    // --------------------------------------------------------------------- //

    function test_ExecuteValid() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);

        vm.prank(relayer);
        forwarder.execute(req, sig);

        assertEq(recipient.lastSender(), alice, "recipient must see alice as sender");
        assertEq(forwarder.nonces(alice), 1, "nonce increments");
        assertEq(recipient.pingCount(), 1);
        assertEq(address(forwarder).balance, 0, "no eth retained");
    }

    function test_RealSenderIsNotRelayer() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        vm.prank(relayer);
        forwarder.execute(req, sig);
        assertTrue(recipient.lastSender() != relayer, "must not be relayer");
        assertTrue(recipient.lastSender() != address(forwarder), "must not be forwarder");
    }

    function test_MsgDataStrippedOfSuffix() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        vm.prank(relayer);
        forwarder.execute(req, sig);
        // recipient recorded _msgData() which must equal the original ping calldata (no 20-byte suffix)
        assertEq(recipient.lastData(), PAYLOAD);
    }

    function test_Verify_TrueForValid() public view {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        assertTrue(forwarder.verify(req, sig));
    }

    function test_Verify_FalseAfterExecution() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        forwarder.execute(req, sig);
        assertFalse(forwarder.verify(req, sig), "nonce consumed => invalid");
    }

    function test_Verify_FalseWhenExpired() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        req.deadline = uint48(block.timestamp - 1);
        bytes memory sig = _sign(aliceKey, req);
        assertFalse(forwarder.verify(req, sig));
    }

    function test_DomainSeparatorNonZero() public view {
        assertTrue(forwarder.domainSeparator() != bytes32(0));
    }

    function test_HashRequestDeterministic() public view {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        assertEq(forwarder.hashRequest(req), forwarder.hashRequest(req));
    }

    // --------------------------------------------------------------------- //
    //                       Signature / tamper rejection                    //
    // --------------------------------------------------------------------- //

    function test_RevertWhen_WrongSigner() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(bobKey, req); // bob signs a request that claims from=alice
        vm.expectRevert(abi.encodeWithSelector(Forwarder.InvalidSigner.selector, alice));
        forwarder.execute(req, sig);
    }

    function test_RevertWhen_TamperedTo() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        req.to = address(0xBEEF);
        vm.expectRevert(abi.encodeWithSelector(Forwarder.InvalidSigner.selector, alice));
        forwarder.execute(req, sig);
    }

    function test_RevertWhen_TamperedValue() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        req.value = 1 ether;
        vm.deal(address(this), 1 ether);
        // send matching msg.value so the value-mismatch guard passes and the signature check is reached
        vm.expectRevert(abi.encodeWithSelector(Forwarder.InvalidSigner.selector, alice));
        forwarder.execute{value: 1 ether}(req, sig);
    }

    function test_RevertWhen_TamperedGas() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        req.gas = 123_456;
        vm.expectRevert(abi.encodeWithSelector(Forwarder.InvalidSigner.selector, alice));
        forwarder.execute(req, sig);
    }

    function test_RevertWhen_TamperedNonce() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        req.nonce = 5;
        vm.expectRevert(abi.encodeWithSelector(Forwarder.InvalidNonce.selector, alice, 0, 5));
        forwarder.execute(req, sig);
    }

    function test_RevertWhen_TamperedDeadline() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        req.deadline = uint48(block.timestamp + 2 hours); // still valid time, but not what was signed
        vm.expectRevert(abi.encodeWithSelector(Forwarder.InvalidSigner.selector, alice));
        forwarder.execute(req, sig);
    }

    function test_RevertWhen_TamperedData() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        req.data = abi.encodeCall(SampleRecipient.ping, ("different"));
        vm.expectRevert(abi.encodeWithSelector(Forwarder.InvalidSigner.selector, alice));
        forwarder.execute(req, sig);
    }

    function test_RevertWhen_Expired() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        req.deadline = uint48(block.timestamp - 1);
        bytes memory sig = _sign(aliceKey, req);
        vm.expectRevert(abi.encodeWithSelector(Forwarder.ExpiredRequest.selector, req.deadline));
        forwarder.execute(req, sig);
    }

    // --------------------------------------------------------------------- //
    //                              Nonce / replay                           //
    // --------------------------------------------------------------------- //

    function test_RevertWhen_Replay() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        forwarder.execute(req, sig);
        vm.expectRevert(abi.encodeWithSelector(Forwarder.InvalidNonce.selector, alice, 1, 0));
        forwarder.execute(req, sig); // replay same request => nonce mismatch
    }

    function test_RevertWhen_OutOfOrderNonce() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        req.nonce = 1; // skips 0
        bytes memory sig = _sign(aliceKey, req);
        vm.expectRevert(abi.encodeWithSelector(Forwarder.InvalidNonce.selector, alice, 0, 1));
        forwarder.execute(req, sig);
    }

    function test_NonceIncrementsSequentially() public {
        for (uint256 i = 0; i < 3; ++i) {
            Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
            forwarder.execute(req, _sign(aliceKey, req));
            assertEq(forwarder.nonces(alice), i + 1);
        }
    }

    function test_TwoFromAddressesIndependent() public {
        Forwarder.ForwardRequest memory ra = _req(alice, address(recipient), 0, _pingData());
        forwarder.execute(ra, _sign(aliceKey, ra));
        assertEq(forwarder.nonces(alice), 1);
        assertEq(forwarder.nonces(bob), 0, "bob unaffected by alice");

        Forwarder.ForwardRequest memory rb = _req(bob, address(recipient), 0, _pingData());
        forwarder.execute(rb, _sign(bobKey, rb));
        assertEq(forwarder.nonces(bob), 1);
        assertEq(forwarder.nonces(alice), 1);
    }

    // --------------------------------------------------------------------- //
    //                                ERC-1271                               //
    // --------------------------------------------------------------------- //

    function test_ExecuteWith1271Wallet() public {
        (address walletOwner, uint256 walletOwnerKey) = makeAddrAndKey("walletOwner");
        ERC1271Wallet wallet = new ERC1271Wallet(walletOwner);

        Forwarder.ForwardRequest memory req = _req(address(wallet), address(recipient), 0, _pingData());
        bytes memory sig = _sign(walletOwnerKey, req); // owner's EOA signature validates for the wallet

        forwarder.execute(req, sig);
        assertEq(recipient.lastSender(), address(wallet), "recipient sees the smart wallet as sender");
        assertEq(forwarder.nonces(address(wallet)), 1);
    }

    function test_RevertWhen_1271WrongOwnerSig() public {
        (address walletOwner,) = makeAddrAndKey("walletOwner2");
        ERC1271Wallet wallet = new ERC1271Wallet(walletOwner);

        Forwarder.ForwardRequest memory req = _req(address(wallet), address(recipient), 0, _pingData());
        bytes memory sig = _sign(bobKey, req); // not the wallet owner
        vm.expectRevert(abi.encodeWithSelector(Forwarder.InvalidSigner.selector, address(wallet)));
        forwarder.execute(req, sig);
    }

    // --------------------------------------------------------------------- //
    //                     Trust boundary / real-sender                      //
    // --------------------------------------------------------------------- //

    function test_DirectCallSeesMsgSender() public {
        // A direct (non-forwarded) call: recipient sees the actual msg.sender.
        vm.prank(alice);
        recipient.ping(PAYLOAD);
        assertEq(recipient.lastSender(), alice);
    }

    function test_NonTrustingRecipientIgnoresAppendedSender() public {
        // This recipient trusts a *different* forwarder, so it ignores our appended sender bytes.
        SampleRecipient other = new SampleRecipient(address(0xDEAD));
        Forwarder.ForwardRequest memory req = _req(alice, address(other), 0, _pingData());
        bytes memory sig = _sign(aliceKey, req);

        vm.prank(relayer);
        forwarder.execute(req, sig);

        // Because `other` does not trust this forwarder, _msgSender() falls back to msg.sender == forwarder.
        assertEq(other.lastSender(), address(forwarder), "untrusted forwarder => suffix ignored");
        assertTrue(other.lastSender() != alice, "spoofed sender must NOT be honored");
    }

    // --------------------------------------------------------------------- //
    //                            Value handling                             //
    // --------------------------------------------------------------------- //

    function test_ValueDeliveredToRecipient() public {
        uint256 amount = 2 ether;
        vm.deal(relayer, amount);
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), amount, _pingData());
        bytes memory sig = _sign(aliceKey, req);

        vm.prank(relayer);
        forwarder.execute{value: amount}(req, sig);

        assertEq(address(recipient).balance, amount, "value forwarded to recipient");
        assertEq(recipient.lastValue(), amount);
        assertEq(address(forwarder).balance, 0, "no eth retained");
    }

    function test_RevertWhen_ValueTooLittle() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 1 ether, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        vm.deal(address(this), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(Forwarder.MismatchedValue.selector, 1 ether, 0.5 ether));
        forwarder.execute{value: 0.5 ether}(req, sig);
    }

    function test_RevertWhen_ValueTooMuch() public {
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 1 ether, _pingData());
        bytes memory sig = _sign(aliceKey, req);
        vm.deal(address(this), 2 ether);
        vm.expectRevert(abi.encodeWithSelector(Forwarder.MismatchedValue.selector, 1 ether, 2 ether));
        forwarder.execute{value: 2 ether}(req, sig);
    }

    function test_RevertWhen_InnerCallReverts() public {
        Forwarder.ForwardRequest memory req =
            _req(alice, address(recipient), 0, abi.encodeCall(SampleRecipient.boom, ()));
        bytes memory sig = _sign(aliceKey, req);
        vm.expectRevert(Forwarder.FailedInnerCall.selector);
        forwarder.execute(req, sig);
        assertEq(forwarder.nonces(alice), 0, "nonce rolled back on revert");
        assertEq(address(forwarder).balance, 0);
    }

    // --------------------------------------------------------------------- //
    //                              Reentrancy                               //
    // --------------------------------------------------------------------- //

    function test_ReentrancyCannotReplayNonce() public {
        ReentrantRecipient re = new ReentrantRecipient(forwarder);
        Forwarder.ForwardRequest memory req =
            _req(alice, address(re), 0, abi.encodeCall(ReentrantRecipient.reenter, ()));
        bytes memory sig = _sign(aliceKey, req);
        re.arm(req, sig);

        forwarder.execute(req, sig);

        assertTrue(re.reentryReverted(), "reentrant replay must revert on nonce");
        assertEq(forwarder.nonces(alice), 1, "nonce advanced exactly once");
        assertEq(address(forwarder).balance, 0);
    }

    // --------------------------------------------------------------------- //
    //                          63/64 gas griefing                           //
    // --------------------------------------------------------------------- //

    function test_GasGriefingDefenseReverts() public {
        GasBurner burner = new GasBurner();
        Forwarder.ForwardRequest memory req = _req(alice, address(burner), 0, abi.encodeCall(GasBurner.guzzle, ()));
        req.gas = 30_000_000; // signer asks for a lot; a starved relayer cannot honor it undetected
        bytes memory sig = _sign(aliceKey, req);

        Forwarder.ForwardRequest[] memory reqs = new Forwarder.ForwardRequest[](1);
        bytes[] memory sigs = new bytes[](1);
        reqs[0] = req;
        sigs[0] = sig;

        // Non-atomic batch: without the 63/64 guard the starved inner call would just be "refunded"
        // and the batch would succeed. The guard turns starvation into a whole-tx revert.
        (bool ok,) = address(forwarder).call{gas: 600_000}(
            abi.encodeCall(Forwarder.batchExecute, (reqs, sigs, payable(makeAddr("refund"))))
        );
        assertFalse(ok, "starved forwarding must revert via 63/64 check");
    }

    function test_HonestGasSucceeds() public {
        // A tight-but-sufficient gas budget honestly honored: executes fine.
        Forwarder.ForwardRequest memory req = _req(alice, address(recipient), 0, _pingData());
        req.gas = 200_000;
        bytes memory sig = _sign(aliceKey, req);
        forwarder.execute(req, sig);
        assertEq(recipient.pingCount(), 1);
    }

    // --------------------------------------------------------------------- //
    //                               Batch                                   //
    // --------------------------------------------------------------------- //

    function test_BatchExecuteAll() public {
        Forwarder.ForwardRequest[] memory reqs = new Forwarder.ForwardRequest[](2);
        bytes[] memory sigs = new bytes[](2);

        reqs[0] = _req(alice, address(recipient), 0, _pingData());
        sigs[0] = _sign(aliceKey, reqs[0]);
        reqs[1] = _req(bob, address(recipient), 0, _pingData());
        sigs[1] = _sign(bobKey, reqs[1]);

        forwarder.batchExecute(reqs, sigs, payable(makeAddr("refund")));

        assertEq(forwarder.nonces(alice), 1);
        assertEq(forwarder.nonces(bob), 1);
        assertEq(recipient.pingCount(), 2);
        assertEq(address(forwarder).balance, 0);
    }

    function test_BatchSkipsInvalidAndRefunds() public {
        address refund = makeAddr("refund");
        vm.deal(relayer, 3 ether);

        Forwarder.ForwardRequest[] memory reqs = new Forwarder.ForwardRequest[](2);
        bytes[] memory sigs = new bytes[](2);

        // valid, carries 1 ether
        reqs[0] = _req(alice, address(recipient), 1 ether, _pingData());
        sigs[0] = _sign(aliceKey, reqs[0]);
        // invalid signature, carries 2 ether that must be refunded
        reqs[1] = _req(bob, address(recipient), 2 ether, _pingData());
        sigs[1] = _sign(aliceKey, reqs[1]); // wrong signer => skipped

        vm.prank(relayer);
        forwarder.batchExecute{value: 3 ether}(reqs, sigs, payable(refund));

        assertEq(forwarder.nonces(alice), 1, "valid one executed");
        assertEq(forwarder.nonces(bob), 0, "invalid one skipped");
        assertEq(address(recipient).balance, 1 ether, "only valid value delivered");
        assertEq(refund.balance, 2 ether, "unused value refunded");
        assertEq(address(forwarder).balance, 0, "no eth retained");
    }

    function test_BatchAtomicRevertsOnInvalid() public {
        Forwarder.ForwardRequest[] memory reqs = new Forwarder.ForwardRequest[](2);
        bytes[] memory sigs = new bytes[](2);

        reqs[0] = _req(alice, address(recipient), 0, _pingData());
        sigs[0] = _sign(aliceKey, reqs[0]);
        reqs[1] = _req(bob, address(recipient), 0, _pingData());
        sigs[1] = _sign(aliceKey, reqs[1]); // wrong signer

        // refundReceiver == address(0) => atomic; the invalid request must revert the batch.
        vm.expectRevert(abi.encodeWithSelector(Forwarder.InvalidSigner.selector, bob));
        forwarder.batchExecute(reqs, sigs, payable(address(0)));
        assertEq(forwarder.nonces(alice), 0, "atomic revert rolls back the whole batch");
    }

    function test_BatchInnerRevertRefundsNonAtomic() public {
        address refund = makeAddr("refund");
        vm.deal(relayer, 1 ether);

        Forwarder.ForwardRequest[] memory reqs = new Forwarder.ForwardRequest[](1);
        bytes[] memory sigs = new bytes[](1);
        reqs[0] = _req(alice, address(recipient), 1 ether, abi.encodeCall(SampleRecipient.boom, ()));
        sigs[0] = _sign(aliceKey, reqs[0]);

        vm.prank(relayer);
        forwarder.batchExecute{value: 1 ether}(reqs, sigs, payable(refund));

        assertEq(forwarder.nonces(alice), 1, "nonce consumed even though inner reverted");
        assertEq(refund.balance, 1 ether, "value of reverting call refunded");
        assertEq(address(forwarder).balance, 0);
    }

    function test_RevertWhen_BatchValueMismatch() public {
        Forwarder.ForwardRequest[] memory reqs = new Forwarder.ForwardRequest[](1);
        bytes[] memory sigs = new bytes[](1);
        reqs[0] = _req(alice, address(recipient), 1 ether, _pingData());
        sigs[0] = _sign(aliceKey, reqs[0]);
        vm.deal(address(this), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(Forwarder.MismatchedValue.selector, 1 ether, 0.5 ether));
        forwarder.batchExecute{value: 0.5 ether}(reqs, sigs, payable(makeAddr("refund")));
    }

    function test_RevertWhen_BatchMismatchedArrays() public {
        Forwarder.ForwardRequest[] memory reqs = new Forwarder.ForwardRequest[](2);
        bytes[] memory sigs = new bytes[](1);
        reqs[0] = _req(alice, address(recipient), 0, _pingData());
        reqs[1] = _req(bob, address(recipient), 0, _pingData());
        sigs[0] = _sign(aliceKey, reqs[0]);
        vm.expectRevert(Forwarder.MismatchedArrayLengths.selector);
        forwarder.batchExecute(reqs, sigs, payable(makeAddr("refund")));
    }
}
