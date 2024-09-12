// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BN256Addition {
  
  function callBn256Add(uint256 ax, uint256 ay, uint256 bx, uint256 by) public returns (bytes32[2] memory result) {
    bytes32[4] memory input;
    input[0] = bytes32(ax);
    input[1] = bytes32(ay);
    input[2] = bytes32(bx);
    input[3] = bytes32(by);
    
    assembly {
        let success := call(gas(), 0x06, 0, input, 0x80, result, 0x40)
        switch success
        case 0 {
            revert(0, 0)
        }
    }
  }

}

// Source for Public Key points : https://www.linkedin.com/pulse/signatures-from-bn-256-elliptic-curves-buchanan-obe-phd-fbcs/

        // 51034946685813001170817435102353414123470700731734176493660185826748147116266
        // 64210743524728530290185905551942812616400571488225773882109119010482573127691

        // 15434778760021406666927668640057214805094329177828734336347158339868964471406
        // 1645883428099392092679734410866463344800887723192890577720280731380716208522




