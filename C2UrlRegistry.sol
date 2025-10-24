// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract C2UrlRegistry {
    string public c2Url;
    address public owner;

    event C2UrlChanged(string newUrl);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can call this function");
        _;
    }

    function setC2Url(string memory _url) public onlyOwner {
        c2Url = _url;
        emit C2UrlChanged(_url);
    }

    function getC2Url() public view returns (string memory) {
        return c2Url;
    }
}
