/**
 * @file Multi-Factor Derived Key Threshold Hints
 * @copyright Multifactor, Inc. 2022–2025
 *
 * @description
 * Add factor hints to a multi-factor derived key
 *
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 */

const { decrypt, hkdf } = require('../../crypt')
const { extract } = require('../../integrity')
const crypto = require('crypto')

/**
 * Get a (probabilistic) hint for a factor to (usually) help verify which factor is wrong.
 * Makes the key slightly easier to brute-force (about 2^bits times easier), so be careful.
 *
 * @example
 * const setup = await mfkdf.setup.key([
 *   await mfkdf.setup.factors.password("password1", {
 *     id: "password1",
 *   }),
 * ]);
 *
 * const hint = await setup.getHint("password1", 7); // -> 1011000
 *
 * const derived = await mfkdf.derive.key(setup.policy, {
 *   password1: mfkdf.derive.factors.password("password1"),
 * });
 *
 * const hint2 = await derived.getHint("password1", 7); // -> 1011000
 * hint2.should.equal(hint);
 *
 * @param {string} factor - Factor ID to add hint for
 * @param {string} [bits=7] - Bits of entropy to reveal (default: 7 bits; more is risky)
 * @returns {Buffer} Derived sub-key
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 2.0.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function getHint (factor, bits = 7) {
  if (typeof factor !== 'string' || factor.length === 0) {
    throw new TypeError('factor id must be a non-empty string')
  }
  if (typeof bits !== 'number' || bits < 1 || bits > 256) {
    throw new TypeError('bits must be a number between 1 and 256')
  }

  // get factor data
  const factorData = this.policy.factors.find((f) => f.id === factor)
  if (!factorData) {
    throw new RangeError('factor id not found in policy')
  }
  const pad = Buffer.from(factorData.secret, 'base64')
  const secretKey = Buffer.from(
    await hkdf(
      'sha256',
      this.key,
      Buffer.from(factorData.salt, 'base64'),
      'mfkdf2:factor:secret:' + factorData.id,
      32
    )
  )
  const factorMaterial = decrypt(pad, secretKey)
  const buffer = Buffer.from(
    await hkdf(
      'sha256',
      factorMaterial,
      Buffer.from(factorData.salt, 'base64'),
      'mfkdf2:factor:hint:' + factorData.id,
      32
    )
  )

  const binaryString = [...buffer]
    .map((byte) => byte.toString(2).padStart(8, '0'))
    .reduce((acc, bits) => acc + bits, '')

  return binaryString.slice(-1 * bits)
}
module.exports.getHint = getHint

/**
 * Add a (probabilistic) hint for a factor to (usually) help verify which factor is wrong.
 * Permanently adds the hint to the key policy, and throws an error when the factor is wrong.
 * Makes the key slightly easier to brute-force (about 2^bits times easier), so be careful.
 * Overrides the existing hint if one already exists.
 *
 * @example
 * const setup = await mfkdf.setup.key(
 *   [
 *     await mfkdf.setup.factors.password('password1', {
 *       id: 'password1'
 *     })
 *   ],
 *   {
 *     integrity: false
 *   }
 * )
 *
 * await setup.addHint('password1')
 *
 * await mfkdf.derive
 *   .key(
 *     setup.policy,
 *     {
 *       password1: mfkdf.derive.factors.password('password2')
 *     },
 *     false
 *   )
 *   .should.be.rejectedWith(RangeError)
 *
 * @param {string} factor - Factor ID to add hint for
 * @param {string} [bits=7] - Bits of entropy to reveal (default: 7 bits; more is risky)
 * @returns {Buffer} Derived sub-key
 * @author Vivek Nair (https://nair.me) <vivek@nair.me>
 * @since 2.0.0
 * @memberOf MFKDFDerivedKey
 * @async
 */
async function addHint (factor, bits = 7) {
  
  if (this.policy.hmac) {
    const integrityKey = await hkdf(
      'sha256',
      this.key,
      Buffer.from(this.policy.salt, 'base64'),
      'mfkdf2:integrity',
      32
    )
    const integrityData = await extract(this.policy)
    const hmac = crypto
    .createHmac('sha256', integrityKey)
    .update(integrityData)
    .digest('base64')
    if (this.policy.hmac !== hmac) {
      throw new RangeError('key policy integrity check failed')
    }
  }

  const hint = await this.getHint(factor, bits)
  const factorData = this.policy.factors.find((f) => f.id === factor)
  factorData.hint = hint

  if (this.policy.hmac) {
    const newPolicyData = await extract(this.policy)
    const newHmac = crypto.createHmac('sha256', integrityKey)
    newHmac.update(newPolicyData)
    this.policy.hmac = newHmac.digest('base64')
  }
}
module.exports.addHint = addHint
