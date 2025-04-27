"use strict";

const blindSig = require('blind-signatures');
const helpers = require('./utils.js');

const RIS_SIZE = 20;
const ID_TAG = "ID_TOKEN";
const BANK_TITLE = "VIRTUAL_SAVINGS_BANK";

class Token {
  constructor(holder, amount, modulus, exponent) {
    this.amount = amount;
    this.modulus = modulus;
    this.exponent = exponent;

    this.tokenId = helpers.makeGUID();
    this.leftSet = [];
    this.rightSet = [];

    const leftHashes = [];
    const rightHashes = [];

    for (let i = 0; i < RIS_SIZE; i++) {
      const { key, ciphertext } = helpers.makeOTP({ string: `${ID_TAG}:${holder}` });

      this.leftSet.push(key);
      leftHashes.push(helpers.hash(key));

      this.rightSet.push(ciphertext);
      rightHashes.push(helpers.hash(ciphertext));
    }

    this.payload = `${BANK_TITLE}-${this.amount}-${this.tokenId}-${leftHashes.join(',')}-${rightHashes.join(',')}`;

    this._performBlinding();
  }

  _performBlinding() {
    const { blinded, r } = blindSig.blind({
      message: this.toString(),
      N: this.modulus,
      E: this.exponent
    });

    this.blindedMessage = blinded;
    this.blindingFactor = r;
  }

  removeBlinding() {
    this.signature = blindSig.unblind({
      signed: this.signature,
      N: this.modulus,
      r: this.blindingFactor
    });
  }

  toString() {
    return this.payload;
  }

  discloseRis(useLeft, index) {
    return useLeft ? this.leftSet[index] : this.rightSet[index];
  }
}

module.exports = {
  Token,
  RIS_SIZE,
  ID_TAG,
  BANK_TITLE
};
