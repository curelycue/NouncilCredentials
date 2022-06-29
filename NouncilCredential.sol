//
// ╔╦╗╔═╗╦╔═╔═╗╦═╗  ╔╗ ╔═╗╔╦╗╔═╗╔═╗╔═╗
// ║║║╠═╣╠╩╗║╣ ╠╦╝  ╠╩╗╠═╣ ║║║ ╦║╣ ╚═╗
// ╩ ╩╩ ╩╩ ╩╚═╝╩╚═  ╚═╝╩ ╩═╩╝╚═╝╚═╝╚═╝
//

/// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity 0.8.4;

import "./BadgeRoles.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/// @title Soulbound Credentials for Nouncillors (Nouns DAO)
/// @author Eduard Ioan Stoica @waterdrops.
/// @notice NouncilCredential to manage roots and activate Soulbound Nouncil Credentials by redeemers
/// @dev All function calls are currently implemented without side effects through TDD approach
/// @dev OpenZeppelin Library is used for secure contract development


contract NouncilCredentials is Ownable, ERC721URIStorage {
    /// @dev Libraries
    using MerkleProof for bytes32[];

    string public baseTokenURI;

    bytes32[] private roots;

    mapping(uint256 => BadgeTemplate) public totalCredentials;
    mapping(uint256 => uint256) public redeemedCredentials;

    /// @dev Events

    event CredentialActivated(uint256 indexed tokenId);

    constructor(MinimalForwarder forwarder, address multisig)
        ERC721("MakerBadges", "MAKER")
        BadgeRoles(forwarder, multisig)
    {
        baseTokenURI = "https://ipfs.io/ipfs/";
    }

    /// @notice Cast to uint96
    /// @dev Revert on overflow
    /// @param x Value to cast
    function toUint96(uint256 x) internal pure returns (uint96 z) {
        require((z = uint96(x)) == x, "MakerBadges/uint96-overflow");
    }

    /// @notice Set the baseURI
    /// @dev Update the baseURI specified in the constructor
    /// @param baseURI New baseURI
    function setBaseURI(string calldata baseURI) external onlyOwner{
        baseTokenURI = baseURI;
    }

    /// @notice Set Merkle Tree Root Hashes array
    /// @dev Called by admin to update roots for different address batches by templateId
    /// @param _roots Root hashes of the new Merkle Tree
    function setRootHashes(bytes32[] calldata _roots) external whenNotPaused onlyOwner{
        roots = _roots;
    }

    /// @dev Credentials

    /// @notice Activate Credential by redeemers
    /// @dev Verify if the caller is a redeemer
    /// @param proof Merkle Proof
    /// @param tokenURI  Token URI
    /// @return True If the new Credential is Activated
    function activateCredential(
        bytes32[] calldata proof,
        string calldata tokenURI
    ) external whenNotPaused returns (bool) {
        require(
            proof.verify(roots, keccak256(abi.encodePacked(_msgSender()))),
            "NouncilCredentials/only-redeemer"
        );

        uint256 _tokenId = _getTokenId(_msgSender());

        /// @dev Increase the quantities
        templateQuantities[templateId] += 1;

        require(_mintWithTokenURI(_msgSender(), _tokenId, tokenURI), "NouncilCredentials/credential-not-minted");

        emit CredentialActivated(_tokenId);
        return true;
    }

    /// @notice Getter function for redeemer associated with the tokenId
    /// @dev Check if the tokenId exists
    /// @param tokenId Token Id of the Badge
    /// @return redeemer Redeemer address associated with the tokenId
    function getCredentialRedeemer(uint256 tokenId) external view returns (address redeemer) {
        require(_exists(tokenId), "NouncilCredentials/invalid-token-id");
        (redeemer, ) = _unpackTokenId(tokenId);
    }

    /// @notice Getter function for tokenId associated with redeemer and templateId
    /// @dev Check if the templateId exists
    /// @dev Check if the tokenId exists
    /// @param redeemer Redeemer address
    /// @param templateId Template Id
    /// @return tokenId Token Id associated with the redeemer and templateId
    function getTokenId(address redeemer) external view returns (uint256 tokenId) {
        tokenId = _getTokenId(redeemer);
        require(_exists(tokenId), "NouncilCredentials/invalid-token-id");
    }

    /// @notice ERC721 _transfer() Disabled
    /// @dev _transfer() has been overriden
    /// @dev reverts on transferFrom() and safeTransferFrom()
    function _transfer(
        address,
        address,
        uint256
    ) internal pure override {
        revert("NouncilCredentials/token-transfer-disabled");
    }

    /// @notice Generate tokenId
    /// @dev Augur twist by concatenate redeemer and templateId
    /// @param redeemer Redeemer Address
    /// @param templateId Template Id
    /// @param _tokenId Token Id
    function _getTokenId(address redeemer, uint256 templateId) private pure returns (uint256 _tokenId) {
        bytes memory _tokenIdBytes = abi.encodePacked(redeemer, toUint96(templateId));
        assembly {
            _tokenId := mload(add(_tokenIdBytes, add(0x20, 0)))
        }
    }

    /// @notice Unpack tokenId
    /// @param tokenId Token Id of the Badge
    /// @return redeemer Redeemer Address
    /// @return templateId Template Id
    function _unpackTokenId(uint256 tokenId) private pure returns (address redeemer, uint256 templateId) {
        assembly {
            redeemer := shr(96, and(tokenId, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000))
            templateId := and(tokenId, 0x0000000000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF)
        }
    }

    /// @notice Mint new token with tokenURI
    /// @dev Automatically concatenate baseURI with tokenURI via abi.encodePacked
    /// @param to Owner of the new token
    /// @param tokenId Token Id of the Baddge
    /// @param tokenURI Token URI of the Badge
    /// @return True if the new token is minted
    function _mintWithTokenURI(
        address to,
        uint256 tokenId,
        string calldata tokenURI
    ) private returns (bool) {
        _mint(to, tokenId);
        _setTokenURI(tokenId, tokenURI);
        return true;
    }

    /// @notice Getter function for baseTokenURI
    /// @dev Override _baseURI()
    function _baseURI() internal view override returns (string memory) {
        return baseTokenURI;
    }

    /// @notice IERC165 supportsInterface
    /// @dev supportsInterface has been override
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControlEnumerable, ERC721)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _msgSender() internal view override(Context, BadgeRoles) returns (address sender) {
        return super._msgSender();
    }

    function _msgData() internal view override(Context, BadgeRoles) returns (bytes calldata) {
        return super._msgData();
    }
}