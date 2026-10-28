// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.24;

import {Token} from "./Token.sol";

/// Constant-product pool without fees: the simplest market a sandwich can exploit.
contract Pool {
    Token public immutable a;
    Token public immutable b;
    uint256 public reserveA;
    uint256 public reserveB;

    constructor(Token a_, Token b_) {
        a = a_;
        b = b_;
    }

    function addLiquidity(uint256 amountA, uint256 amountB) external {
        a.transferFrom(msg.sender, address(this), amountA);
        b.transferFrom(msg.sender, address(this), amountB);
        reserveA += amountA;
        reserveB += amountB;
    }

    function quote(bool aToB, uint256 amountIn) public view returns (uint256) {
        (uint256 rin, uint256 rout) = aToB ? (reserveA, reserveB) : (reserveB, reserveA);
        return amountIn * rout / (rin + amountIn);
    }

    function swap(bool aToB, uint256 amountIn, uint256 minOut) external returns (uint256 out) {
        out = quote(aToB, amountIn);
        require(out >= minOut, "slippage");
        (Token tin, Token tout) = aToB ? (a, b) : (b, a);
        tin.transferFrom(msg.sender, address(this), amountIn);
        tout.transfer(msg.sender, out);
        if (aToB) {
            reserveA += amountIn;
            reserveB -= out;
        } else {
            reserveB += amountIn;
            reserveA -= out;
        }
    }
}
