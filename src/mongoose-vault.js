var objectUtil = require('.//object-util.js')
var _ = require('underscore')
var pick = objectUtil.pick
var mpath = require('mpath')
var setFieldValue = objectUtil.setFieldValue
var deepForEach = require('deep-for-each')

/**
 * Mongoose encryption plugin
 * @module mongoose-encryption
 *
 *
 * @param      {Object}     schema   The schema
 * @param      {Object}     options  Plugin options
 * @param      {string[]}   [options.encryptedFields]  A list of fields to encrypt. Default is to encrypt all fields.
 * @param      {string[]}   [options.excludeFromEncryption]  A list of fields to not encrypt
 * @param      {boolean}    [options.decryptPostSave=true]  Whether to automatically decrypt documents in the application after saving them (faster if false)
 * @param      {string}     [options.keyName] If you update the Model name of the schema, this should be set to its original name
 * @param      {string}     [options.keyCreationKeyType] This can be set when encryption key is expected to be created. See https://www.vaultproject.io/api/secret/transit/index.html#type-1
 * @param      {boolean}     [options.keyCreationConvergentEncryption] Needs to be true if the key is expected to be created and findByEncryptedField should be supported. see https://www.vaultproject.io/api/secret/transit/index.html#convergent_encryption-1
 * @return     {undefined}
 */

var mongooseVault = function (schema, options) {
  var encryptedFields, excludedFields, vault
  // if(!options.vault) throw new Error("vault must be specified.")

  _.defaults(options, {
    keyName: 'per_collection',
    middleware: true, // allow for skipping middleware with false
    decryptPostSave: true // allow for skipping the decryption after save for improved performance
  })

  // Set defaults for the key creations during transit/encrypt request
  const keyCreationDefaults = {}
  if (options.keyCreationKeyType) keyCreationDefaults['type'] = options.keyCreationKeyType
  if (options.keyCreationConvergentEncryption) keyCreationDefaults['convergent_encryption'] = options.keyCreationConvergentEncryption

  // Get the generator for the keyName
  let keyNameGenerator = ((mode) => {
    if (mode === 'per_collection') return (collection, doc) => collection.name
    else if (mode === 'per_document') return (collection, doc) => [collection.name, doc.id].join('-')
    else if (typeof mode === 'function') return mode
    else if (typeof mode === 'string') return () => mode
    else throw new Error('invalid keyName')
  })(options.keyName)

  if (options.encryptedFields) {
    encryptedFields = _.difference(options.encryptedFields, ['_ct'])
    encryptedFields.forEach(function (field) {
      let fieldSchema = schema.paths[field]
      if (!fieldSchema) throw new Error(`unknown field ${field}`)
      if (fieldSchema.instance !== 'String') throw new Error(`'So far, only Strings are supported as encrypted Field. ${field} is a ${fieldSchema.instance}. Create a FeatureRequest if you wish to support more types.`)
    })
  } else {
    excludedFields = _.union(['_id', '_ct'], options.excludeFromEncryption)
    encryptedFields = _.chain(schema.paths)
      .filter(function (pathDetails) { // exclude indexed fields
        return !pathDetails._index
      })
      .filter(function (pathDetails) { // exclude indexed fields
        return pathDetails.instance === 'String'
      })
      .pluck('path') // get path name
      .difference(excludedFields) // exclude excluded fields
      .uniq()
      .value()
  }

  /**  Transformation functions */

  function toBatchObject (obj, encryptedFields, keyName) {
    if (keyName !== 'ciphertext' && keyName !== 'plaintext') throw new Error('invalid argument')
    return encryptedFields
      .map(field => [ field, mpath.get(field, obj) ])
      .filter(([field, objectValue]) => typeof objectValue === 'string' && objectValue !== '')
      .map(([field, value]) => {
        return {
          context: Buffer.from(field).toString('base64'),
          [keyName]: keyName === 'plaintext' ? Buffer.from(value).toString('base64') : value
        }
      })
  }

  function assignFromBatchObject (assignToObject, batchObject, encryptedFields, keyName = 'ciphertext') {
    if (keyName !== 'ciphertext' && keyName !== 'plaintext') throw new Error('invalid argument')

    encryptedFields
        .map(field => [field, mpath.get(field, assignToObject)])
        .filter(([field, objectValue]) => typeof objectValue === 'string' && objectValue !== '')
        .forEach(([field], i) => {
          let value = (keyName === 'plaintext' && typeof batchObject[i][keyName] === 'string'
            ? Buffer.from(batchObject[i][keyName], 'base64').toString('utf8')
            : batchObject[i][keyName])
          setFieldValue(assignToObject, field, value)
        })
  }

  async function alterQuery (queryObject) {
    let query = queryObject.getQuery()
    let encryptionKeyName
    let searchObject = []
    // console.log(query)
    deepForEach(query, (value, key, subject, path) => {
      if (encryptedFields.includes(key)) {
        searchObject.push({
          value,
          key,
          subject,
          batchEntry: {
            context: Buffer.from(key).toString('base64'),
            plaintext: Buffer.from(value).toString('base64')
          }
        })
      }
    })

    if (searchObject.length > 0) {
      try {
        encryptionKeyName = keyNameGenerator(queryObject.model.collection)
      } catch (e) { throw new Error('KeyName cannot be generated during searchPhase. (You cannot have per_document keyName and search for this field): ' + e.message) }
      let encryptionResponse = await vault.write('transit/encrypt/' + encryptionKeyName, Object.assign({ batch_input: searchObject.map(e => e.batchEntry) }, keyCreationDefaults))
      encryptionResponse.data.batch_results.forEach((result, i) => {
        searchObject[i].subject[searchObject[i].key] = result.ciphertext
      })
      queryObject.setQuery(query)
    }
  }

  /** Middleware */

  if (options.middleware) { // defaults to true

    let queryFunctionNames = [
      'countDocuments',
      'deleteMany',
      'find',
      'findOne'
    ]
    queryFunctionNames.forEach(functionName => {
      schema.pre(functionName, async function () {
        await alterQuery(this)
      })
    })

    schema.post('findOne', async function (doc) {
      if (doc) {
        await doc.decrypt()
      }
    })
    schema.post('find', function (docs) {
      // TODO Improve bulk operations to have only single request to vault
      return Promise.all(docs.map(doc => doc.decrypt()))
    })

    schema.pre('save', async function () {
      await this.encrypt()
    })

    if (options.decryptPostSave) { // true by default
      schema.post('save', async (doc) => {
        await doc.decrypt()
      })
    }
  }

  /** Encryption Instance Methods */

  schema.statics.connectVault = function (newVault) {
    vault = newVault
  }

  schema.methods.encrypt = async function () {
    let encryptionKeyName = keyNameGenerator(this.constructor.collection, this)
    let objectToEncrypt = pick(this, encryptedFields, {excludeUndefinedValues: true})
    let batchInput = toBatchObject(objectToEncrypt, encryptedFields, 'plaintext')
    let encryptionResponse = await vault.write('transit/encrypt/' + encryptionKeyName, Object.assign({batch_input: batchInput}, keyCreationDefaults))
    assignFromBatchObject(this, encryptionResponse.data.batch_results, encryptedFields, 'ciphertext')
  }

  schema.methods.decrypt = async function () {
    let encryptionKeyName = keyNameGenerator(this.constructor.collection, this)
    let objectToDecrypt = pick(this, encryptedFields, {excludeUndefinedValues: true})
    let batchInput = toBatchObject(objectToDecrypt, encryptedFields, 'ciphertext')
    let decryptionResponse = await vault.write('transit/decrypt/' + encryptionKeyName, Object.assign({ batch_input: batchInput }, keyCreationDefaults))
    assignFromBatchObject(this, decryptionResponse.data.batch_results, encryptedFields, 'plaintext')
  }
}

module.exports = mongooseVault
