// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MetadataStorage {
    struct Metadata {
        string data;
    }

    mapping(string => Metadata) private fileMetadata;
    address public owner;

    event AccessAttempt(string fid, address accessor, bool success);

    constructor() {
        owner = msg.sender;
    }

    function storeMetadata(string memory fid, string memory jsonData) public {
        require(msg.sender == owner, "Only owner can store metadata.");
        require(bytes(fileMetadata[fid].data).length == 0, "FID already used.");
        fileMetadata[fid] = Metadata(jsonData);
    }

    function getMetadata(string memory fid) public view returns (string memory) {
        require(bytes(fileMetadata[fid].data).length > 0, "Metadata not found.");
        return fileMetadata[fid].data;
    }

    function logAccess(string memory fid, bool success) public {
        emit AccessAttempt(fid, msg.sender, success);
    }
}
