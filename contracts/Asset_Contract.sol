// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;
pragma abicoder v2;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

library TokenIdentifiers {
    uint8 constant ADDRESS_BITS = 160;
    uint8 constant INDEX_BITS = 56;
    uint8 constant SUPPLY_BITS = 40;

    uint256 constant SUPPLY_MASK = (uint256(1) << SUPPLY_BITS) - 1;
    uint256 constant INDEX_MASK =
        ((uint256(1) << INDEX_BITS) - 1) ^ SUPPLY_MASK;

    function tokenMaxSupply(uint256 _id) internal pure returns (uint256) {
        return _id & SUPPLY_MASK;
    }

    function tokenIndex(uint256 _id) internal pure returns (uint256) {
        return _id & INDEX_MASK;
    }

    function tokenCreator(uint256 _id) internal pure returns (address) {
        return address(uint160(_id >> (INDEX_BITS + SUPPLY_BITS)));
    }
}

abstract contract ERC1155Pausable is ERC1155, Pausable {
    /**
     * @dev See {ERC1155-_beforeTokenTransfer}.
     *
     * Requirements:
     *
     * - the contract must not be paused.
     */
    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual override {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);

        require(!paused(), "ERC1155Pausable: token transfer while paused");
    }
}

abstract contract ERC1155Burnable is ERC1155Pausable {
    function burn(
        address account,
        uint256 id,
        uint256 value
    ) public virtual {
        require(
            account == _msgSender() || isApprovedForAll(account, _msgSender()),
            "ERC1155: caller is not owner nor approved"
        );

        _burn(account, id, value);
    }

    function burnBatch(
        address account,
        uint256[] memory ids,
        uint256[] memory values
    ) public virtual {
        require(
            account == _msgSender() || isApprovedForAll(account, _msgSender()),
            "ERC1155: caller is not owner nor approved"
        );

        _burnBatch(account, ids, values);
    }
}

abstract contract ERC1155Supply is ERC1155Burnable {
    mapping(uint256 => uint256) private _totalSupply;

    /**
     * @dev Total amount of tokens in with a given id.
     */
    function totalSupply(uint256 id) public view virtual returns (uint256) {
        return _totalSupply[id];
    }

    /**
     * @dev Indicates whether any token exist with a given id, or not.
     */
    function exists(uint256 id) public view virtual returns (bool) {
        return ERC1155Supply.totalSupply(id) > 0;
    }

    /**
     * @dev See {ERC1155-_beforeTokenTransfer}.
     */
    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual override {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);

        if (from == address(0)) {
            for (uint256 i = 0; i < ids.length; ++i) {
                _totalSupply[ids[i]] += amounts[i];
            }
        }

        if (to == address(0)) {
            for (uint256 i = 0; i < ids.length; ++i) {
                uint256 id = ids[i];
                uint256 amount = amounts[i];
                uint256 supply = _totalSupply[id];
                require(
                    supply >= amount,
                    "ERC1155: burn amount exceeds totalSupply"
                );
                unchecked {
                    _totalSupply[id] = supply - amount;
                }
            }
        }
    }
}

abstract contract ERC1155URIStorage is ERC1155Supply {
    using Strings for uint256;

    // Optional base URI
    string private _baseURI = "";

    // Optional mapping for token URIs
    mapping(uint256 => string) private _tokenURIs;

    /**
     * @dev See {IERC1155MetadataURI-uri}.
     *
     * This implementation returns the concatenation of the `_baseURI`
     * and the token-specific uri if the latter is set
     *
     * This enables the following behaviors:
     *
     * - if `_tokenURIs[tokenId]` is set, then the result is the concatenation
     *   of `_baseURI` and `_tokenURIs[tokenId]` (keep in mind that `_baseURI`
     *   is empty per default);
     *
     * - if `_tokenURIs[tokenId]` is NOT set then we fallback to `super.uri()`
     *   which in most cases will contain `ERC1155._uri`;
     *
     * - if `_tokenURIs[tokenId]` is NOT set, and if the parents do not have a
     *   uri value set, then the result is empty.
     */
    function uri(uint256 tokenId)
        public
        view
        virtual
        override
        returns (string memory)
    {
        string memory tokenURI = _tokenURIs[tokenId];

        // If token URI is set, concatenate base URI and tokenURI (via abi.encodePacked).
        return
            bytes(tokenURI).length > 0
                ? string(abi.encodePacked(_baseURI, tokenURI))
                : super.uri(tokenId);
    }

    /**
     * @dev Sets `tokenURI` as the tokenURI of `tokenId`.
     */
    function _setURI(uint256 tokenId, string memory tokenURI) internal virtual {
        _tokenURIs[tokenId] = tokenURI;
        emit URI(uri(tokenId), tokenId);
    }

    /**
     * @dev Sets `baseURI` as the `_baseURI` for all tokens
     */
    function _setBaseURI(string memory baseURI) internal virtual {
        _baseURI = baseURI;
    }
}

contract NFT is ERC1155URIStorage, Ownable, ReentrancyGuard {
    using TokenIdentifiers for uint256;

    address public _exchange;

    // "https://dachshi.mypinata.cloud/ipfs/"
    constructor(string memory uri_) ERC1155(uri_) {
        _setBaseURI(uri_);
    }

    function setExchange(address exchange) public virtual onlyOwner {
        _exchange = exchange;
    }

    modifier creatorOnly(uint256 _id) {
        require(msg.sender == _id.tokenCreator(), "Caller is not the creator");
        _;
    }

    modifier exchangeOnly() {
        require(msg.sender == _exchange, "Caller is not the exchange");
        _;
    }

    function mint(
        uint256 _id,
        uint256 _quantity,
        bytes memory _data,
        string memory _uri
    ) public nonReentrant creatorOnly(_id) {
        uint256 alreadyMinted = totalSupply(_id);
        uint256 maxSupply = _id.tokenMaxSupply();

        require(
            _quantity <= maxSupply - alreadyMinted,
            "Cannot mint more than max supply"
        );
        _mint(msg.sender, _id, _quantity, _data);
        if(alreadyMinted == 0){
            _setURI(_id, _uri);
        }
    }

    function mintFromExchange(
        address _to,
        uint256 _id,
        uint256 _quantity,
        bytes memory _data,
        string memory _uri
    ) internal {
        uint256 alreadyMinted = totalSupply(_id);
        uint256 maxSupply = _id.tokenMaxSupply();

        require(_to == _id.tokenCreator(), "Creator does not match");
        require(
            _quantity <= maxSupply - alreadyMinted,
            "Cannot mint more than max supply"
        );
        _mint(_to, _id, _quantity, _data);
        if(alreadyMinted == 0){
            _setURI(_id, _uri);
        }
    }

    function transferFromExchange(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data,
        string memory uri
    ) public nonReentrant exchangeOnly {
        uint256 mintedBalance = balanceOf(from, id);
        if(amount > mintedBalance){
            mintFromExchange(from, id, amount - mintedBalance, data, uri);
        }
        safeTransferFrom(from, to, id, amount, data);
    }
}
