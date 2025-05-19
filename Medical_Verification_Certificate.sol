// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MedLedger {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    struct Credential {
        string holderName;
        string qualification;
        string issueDate;
        string expiryDate;
        string issuer;
        bool isRevoked;
    }

    // Mapping from credential ID to Credential
    mapping(string => Credential) private credentials;

    // Mapping to track authorized issuers
    mapping(address => bool) public authorizedIssuers;

    // Events
    event IssuerAuthorized(address issuer);
    event IssuerRevoked(address issuer);
    event CredentialIssued(string credentialID, string holderName, string issuer);
    event CredentialRevoked(string credentialID);

    // Modifier to restrict functions to admin
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    // Modifier to restrict functions to authorized issuers
    modifier onlyAuthorizedIssuer() {
        require(authorizedIssuers[msg.sender], "Not an authorized issuer");
        _;
    }

    // Function to authorize a new issuer
    function authorizeIssuer(address issuer) external onlyAdmin {
        authorizedIssuers[issuer] = true;
        emit IssuerAuthorized(issuer);
    }

    // Function to revoke an issuer's authorization
    function revokeIssuer(address issuer) external onlyAdmin {
        authorizedIssuers[issuer] = false;
        emit IssuerRevoked(issuer);
    }

    // Function to issue a new credential
    function issueCredential(
        string memory credentialID,
        string memory holderName,
        string memory qualification,
        string memory issueDate,
        string memory expiryDate
    ) external onlyAuthorizedIssuer {
        require(bytes(credentials[credentialID].holderName).length == 0, "Credential already exists");

        credentials[credentialID] = Credential({
            holderName: holderName,
            qualification: qualification,
            issueDate: issueDate,
            expiryDate: expiryDate,
            issuer: getAddressString(msg.sender),
            isRevoked: false
        });

        emit CredentialIssued(credentialID, holderName, getAddressString(msg.sender));
    }

    // Function to revoke an existing credential
    function revokeCredential(string memory credentialID) external onlyAuthorizedIssuer {
        require(bytes(credentials[credentialID].holderName).length != 0, "Credential does not exist");
        require(!credentials[credentialID].isRevoked, "Credential already revoked");

        credentials[credentialID].isRevoked = true;

        emit CredentialRevoked(credentialID);
    }

    // Function to verify a credential
    function verifyCredential(string memory credentialID) external view returns (
        string memory holderName,
        string memory qualification,
        string memory issueDate,
        string memory expiryDate,
        string memory issuer,
        bool isRevoked
    ) {
        require(bytes(credentials[credentialID].holderName).length != 0, "Credential does not exist");

        Credential memory cred = credentials[credentialID];
        return (
            cred.holderName,
            cred.qualification,
            cred.issueDate,
            cred.expiryDate,
            cred.issuer,
            cred.isRevoked
        );
    }

    // Helper function to convert address to string
    function getAddressString(address _addr) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(_addr)));
        bytes memory alphabet = "0123456789abcdef";

        bytes memory str = new bytes(42);
        str[0] = '0';
        str[1] = 'x';
        for (uint i = 0; i < 20; i++) {
            str[2+i*2] = alphabet[uint(uint8(value[i + 12] >> 4))];
            str[3+i*2] = alphabet[uint(uint8(value[i + 12] & 0x0f))];
        }
        return string(str);
    }
}

