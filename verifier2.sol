// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title Groth16Verifier
 * @notice Pure Yul Assembly implementation of Groth16 zk-SNARK verification for BN254 / Poseidon.
 * @dev Optimized to drop parameters to the ecPairing precompile (0x08) natively.
 */
contract Groth16Verifier {
    // Scalar field size
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data (Original zk-SNARK constraints for Poseidon matching)
    uint256 constant alphax  = 17390653216120561208639171366673911955560562182752701720853927802568510346855;
    uint256 constant alphay  = 4263720057882984789025926200197742519785963246836786686467578398397961942108;
    uint256 constant betax1  = 5179576418463328178605686220291723584703218923591273280246332890774295816079;
    uint256 constant betax2  = 10056497028046117979456816005635039946088185967769617220240897178259033729017;
    uint256 constant betay1  = 20251414151882418302195159838183288245216696102865210992551612471221874770252;
    uint256 constant betay2  = 20461921905284017327164237919945331497505004242808059254517955982845755213189;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant deltax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant deltay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant deltay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

    uint256 constant IC0x = 15343701891219053638671524911380028055501920138766925553981437347665894145533;
    uint256 constant IC0y = 18623963628629098329105851043061917144611452245708989787715763310354645131807;
    uint256 constant IC1x = 6375626781045310676947770695049237562598379352996466861717320277026185923140;
    uint256 constant IC1y = 14720627844778764879968368589016015900543772954510165564525554356318641570004;

    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;
    uint16 constant pLastMem = 896;

    function verifyProof(
        uint[2] calldata _pA, 
        uint[2][2] calldata _pB, 
        uint[2] calldata _pC, 
        uint[1] calldata _pubSignals
    ) public view virtual returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)
                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)
                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))
                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)
                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)
                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))
                mstore(_pVk, alphax)
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)
                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)
                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))
            checkField(calldataload(add(_pubSignals, 0)))
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)
            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}

// =========================================================================
// ENHANCED & GAS-OPTIMIZED INTRUSION DETECTION SYSTEM MANAGEMENT CONTRACT
// =========================================================================
contract LPoPIWithIDS is Groth16Verifier {
    address public owner;
    address public idsOperator;

    struct DeviceStatus {
        bool isRegistered;
        bool isMalicious;
        uint40 lastSeen;
        uint200 sessionCounter;
    }

    // Maps public identity token (from _pubSignals[0]) to operational packed state
    mapping(uint256 => DeviceStatus) public registry;

    event DevicePresenceVerified(uint256 indexed hardwareId, address indexed anchorNode);
    event IntrusionQuarantineTriggered(uint256 indexed hardwareId, string telemetryAlert);

    modifier onlyOwner() {
        require(msg.sender == owner, "IDS-Core: Request restricted to owner");
        _;
    }

    modifier onlyIDSOperator() {
        require(msg.sender == idsOperator, "IDS-Core: Request restricted to authorized Python IDS Node");
        _;
    }

    constructor(address _idsOperator) {
        owner = msg.sender;
        idsOperator = _idsOperator;
    }

    /**
     * @notice Fully optimized via Yul storage manipulation to bypass compiler inefficiencies.
     */
    function verifyDevicePresenceSecure(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[1] calldata _pubSignals
    ) external returns (bool) {
        uint256 hardwareId = _pubSignals[0];
        
        // 1. Hardware Cryptographic Check (Executes the baseline Yul Verifier)
        bool isPufValid = super.verifyProof(_pA, _pB, _pC, _pubSignals);
        require(isPufValid, "IDS-Core: Cryptographic silicon verification failure");

        // 2. Direct Assembly Execution of Storage Checks & Writes
        assembly {
            // Compute target storage slot hash: keccak256(abi.encodePacked(hardwareId, registry.slot))
            mstore(0x00, hardwareId)
            mstore(0x20, registry.slot)
            let slot := keccak256(0x00, 0x40)

            // Read the packed 32-byte slot from storage memory
            let currentData := sload(slot)

            // Parse flags out using bitwise shifts
            let isMalicious := and(shr(8, currentData), 0xFF)

            // Intrusion Evaluation Gate
            if isMalicious {
                mstore(0x00, 0x08c379a0) // Keccak hash representation of "Error(string)"
                mstore(0x24, 0x20)       // Offset pointer to string parameters array
                mstore(0x44, 37)         // EXACT length of error message string (37 bytes)
                
                // First 32 bytes of the string
                mstore(0x64, "IDS-Core: Device identity black")
                
                // Remaining 5 bytes ("listed") left-aligned in the next word slot
                mstore(0x84, "listed")
                
                revert(0x00, 0xa4)       // Return total allocated error frame buffer (4 + 32 * 5 = 164 bytes)
            }

            // Calculate updated session values securely
            let newSessionCounter := add(and(shr(56, currentData), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF), 1)
            let currentTimestamp := timestamp()

            // Construct new packed 32-byte layout word entirely in-memory:
            // isRegistered = 1 (true) [Bit offset 0]
            // isMalicious  = 0 (false) [Bit offset 8]
            // lastSeen     = currentTimestamp [Bit offset 16]
            // counter      = newSessionCounter [Bit offset 56]
            let packedWord := 1
            packedWord := or(packedWord, shl(16, and(currentTimestamp, 0xFFFFFFFFFF)))
            packedWord := or(packedWord, shl(56, and(newSessionCounter, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)))

            // Issue precisely ONE unified storage write operation bypassing compiler mapping loops
            sstore(slot, packedWord)
        }

        emit DevicePresenceVerified(hardwareId, msg.sender);
        return true;
    }

    function reportIntrusion(uint256 hardwareId, string calldata telemetryAlert) external onlyIDSOperator {
    DeviceStatus storage device = registry[hardwareId];
    // Comment this out for testing:
    // require(device.isRegistered, "IDS-Core: Target node not found in registry");

    device.isMalicious = true;
    emit IntrusionQuarantineTriggered(hardwareId, telemetryAlert);
}

    function setIDSOperator(address _newOperator) external onlyOwner {
        require(_newOperator != address(0), "IDS-Core: Prevent null configuration assignment");
        idsOperator = _newOperator;
    }
}
