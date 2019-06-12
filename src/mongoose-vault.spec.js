/* global describe, it, describe, before */

require('dotenv').config()
const expect = require('chai').expect
const mongoose = require('mongoose')
const nodeVault = require('node-vault')
const mongooseVault = require('./mongoose-vault')

const Schema = mongoose.Schema

let vault
before(async () => {
  mongoose.connect(process.env.MONGO_CONNECTION_STRING, {useNewUrlParser: true})
  vault = await nodeVault({endpoint: process.env.VAULT_CONNECTION_STRING, token: process.env.VAULT_DEV_ROOT_TOKEN_ID})
  try {
    await vault.mount({mount_point: 'transit', type: 'transit'})
  } catch (e) { /* Already mounted */ }
})
after(async () => {
  mongoose.disconnect()
})

const schemaDefinition = {
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  address: { type: String },
  address2: { type: String },
  email: { type: String },
  objectOfStrings: {
    string1: { type: String },
    string2: { type: String },
    string3: { type: String }
  },
  emptyString: { type: String },
  bool: { type: Boolean },
  num: { type: Number },
  date: { type: Date },
  arr: [ { type: String } ],
  mix: { type: mongoose.Schema.Types.Mixed },
  buf: { type: Buffer },
  idx: { type: String, index: true }
}

var validIdentity = {
  'firstName': 'Max',
  'lastName': 'Mustermann',
  'address': 'Karlstr. 1',
  'email': 'test@test.de',
  'bool': true,
  'num': 42,
  'emptyString': '',
  'objectOfStrings': {
    'string1': 'content1',
    'string2': 'content2',
    'string3': 'content3'
  },
  'date': new Date('2014-05-19T16:39:07.536Z'),
  'arr': ['alpha', 'bravo'],
  'mix': { str: 'A string', bool2: false },
  'buf': Buffer.from('abcdefg'),
  'idx': '10000000'
}

describe('Test Mongoose Vault initialisation and options', function () {
  it('correct defined encryptedFields should work. ', async function () {
    var Identity = new Schema(schemaDefinition)
    expect(() => {
      Identity.plugin(mongooseVault, {
        middleware: true,
        decryptPostSave: true,
        keyCreationConvergentEncryption: true,
        keyName: 'per_document',
        encryptedFields: [ 'firstName', 'lastName', 'objectOfStrings.string1' ]
      })
    }).to.not.throw()
  })
  it('not existing encryptedField should throw error. ', async function () {
    var Identity = new Schema(schemaDefinition)
    expect(() => {
      Identity.plugin(mongooseVault, {
        middleware: true,
        decryptPostSave: true,
        keyCreationConvergentEncryption: true,
        keyName: 'per_document',
        encryptedFields: [ 'firstName', 'lastName', 'objectOfStrings.isNotDefined' ]
      })
    }).to.throw(Error, 'unknown field objectOfStrings.isNotDefined')
  })
  it('existing encryptedField but no String should throw error. ', async function () {
    var Identity = new Schema(schemaDefinition)
    expect(() => {
      Identity.plugin(mongooseVault, {
        middleware: true,
        decryptPostSave: true,
        keyCreationConvergentEncryption: true,
        keyName: 'per_document',
        encryptedFields: [ 'firstName', 'lastName', 'num' ]
      })
    }).to.throw(Error, 'So far, only Strings are supported as encrypted Field. num is a Number. Create a FeatureRequest if you wish to support more types.')
  })
})

describe('Test Mongoose Vault with convergentEncryption disabled', function () {
  // Setup Mongose Schema and Model
  var Identity = new Schema(schemaDefinition)
  var IdentityNoEncryption = new Schema(schemaDefinition)

  Identity.plugin(mongooseVault, {
    middleware: true,
    decryptPostSave: true,
    keyCreationConvergentEncryption: false
  })

  var IdentityModel = mongoose.model('Identity', Identity)
  var IdentityNoEncryptionModel = mongoose.model('IdentityNoEncryption', IdentityNoEncryption, 'identities')

  before(async () => {
    await IdentityModel.deleteMany({})
    await IdentityModel.connectVault(vault)
  })

  it('Mongoose create should encrypt and decrypt the document.', async function () {
    let model = await IdentityModel.create(validIdentity)
    let modelEncrypted = await IdentityNoEncryptionModel.findById(model.id)
    expect(modelEncrypted).property('firstName').to.contain('vault:v1:')
    expect(modelEncrypted).property('lastName').to.contain('vault:v1:')
    expect(modelEncrypted).property('email').to.contain('vault:v1:')
    expect(modelEncrypted).nested.property('objectOfStrings.string1').to.contain('vault:v1:')
    expect(modelEncrypted).nested.property('objectOfStrings.string2').to.contain('vault:v1:')
    expect(model._doc).to.deep.include(validIdentity)
  })

  it('Mongoose encrypt should not include the plaintext Field', async function () {
    let model = new IdentityModel(validIdentity)
    expect(model._doc).to.deep.include(validIdentity)
    await model.encrypt()
    expect(model).property('firstName').to.contain('vault:v1:')
    expect(model).property('lastName').to.contain('vault:v1:')
    expect(model).property('email').to.contain('vault:v1:')
    expect(model).nested.property('objectOfStrings.string1').to.contain('vault:v1:')
    expect(model).nested.property('objectOfStrings.string2').to.contain('vault:v1:')
  })

  it('Mongoose findOne should decrypt', async function () {
    let model = await IdentityModel.create(validIdentity)
    expect(model._doc).to.deep.include(validIdentity)

    let modelNew = await IdentityModel.findById(model.id)
    expect(modelNew._doc).to.deep.include(validIdentity)
  })

  it('Mongoose findById should decrypt', async function () {
    let models = await IdentityModel.find({})
    expect(models).to.be.an('array')
    expect(models).to.have.lengthOf.at.least(2)
    expect(models[0]._doc).deep.to.include(validIdentity)
  })

  it('Mongoose find by encrypted field should not return any', async function () {
    let models = await IdentityModel.find({firstName: 'Max'})
    expect(models).to.be.an('array')
    expect(models).to.have.lengthOf(0)
  })
})

describe('Test Mongoose Vault with convergentEncryption enabled', function () {
  // Setup Mongose Schema and Model
  var Identity2 = new Schema(schemaDefinition)

  Identity2.plugin(mongooseVault, {
    middleware: true,
    decryptPostSave: true,
    // THIS WILL ENABLE SEARCH TO WORK
    keyCreationConvergentEncryption: true
  })

  var Identity2Model = mongoose.model('Identity2', Identity2)

  before(async () => {
    await Identity2Model.deleteMany({})
    await Identity2Model.connectVault(vault)
  })

  it('Mongoose find by encrypted fields should return matching documents', async function () {
    let model = await Identity2Model.create(validIdentity)
    expect(model._doc).to.deep.include(validIdentity)

    let models = await Identity2Model.find({firstName: 'Max'})
    expect(models).to.be.an('array').and.have.lengthOf.at.least(1)
    expect(models[0]._doc).to.deep.include(validIdentity)
  })

  it('Mongoose query builder with encrypted fields should return matching documents', async function () {
    let model = await Identity2Model.create(validIdentity)
    expect(model._doc).to.deep.include(validIdentity)

    let models = await Identity2Model.find({firstName: 'Max'})
    expect(models).to.be.an('array').and.have.lengthOf.at.least(1)
    expect(models[0]._doc).to.deep.include(validIdentity)

    models = await Identity2Model
      .where('objectOfStrings.string1').equals('content1')
      .or([{ 'objectOfStrings.string2': 'content1' }, { 'objectOfStrings.string2': 'content2' }])
    expect(models).to.be.an('array').and.have.lengthOf.at.least(1)
    expect(models[0]._doc).to.deep.include(validIdentity)
  })

  it('Mongoose findOne by encrypted fields should return matching document', async function () {
    let model = await Identity2Model.create(validIdentity)
    expect(model._doc).to.deep.include(validIdentity)

    let models = await Identity2Model.findOne({firstName: 'Max'})
    expect(models._doc).to.deep.include(validIdentity)
  })

  it('Mongoose findOne query builder with encrypted fields should return matching document', async function () {
    let model = await Identity2Model.create(validIdentity)
    expect(model._doc).to.deep.include(validIdentity)

    let models = await Identity2Model.findOne({firstName: 'Max'})
    expect(models._doc).to.deep.include(validIdentity)

    models = await Identity2Model.findOne()
      .where('objectOfStrings.string1').equals('content1')
      .or([{ 'objectOfStrings.string2': 'content1' }, { 'objectOfStrings.string2': 'content2' }])
    expect(models._doc).to.deep.include(validIdentity)
  })
})

describe('Test Mongoose Vault with keyName per_document', function () {
  // Setup Mongose Schema and Model
  var Identity3 = new Schema(schemaDefinition)

  Identity3.plugin(mongooseVault, {
    middleware: true,
    decryptPostSave: true,
    keyCreationConvergentEncryption: true,
    keyName: 'per_document'
  })

  var Identity3Model = mongoose.model('Identity3', Identity3)

  before(async () => {
    await Identity3Model.deleteMany({})
    await Identity3Model.connectVault(vault)
  })

  it('Mongoose create should encrypt and decrypt the document.', async function () {
    let model = await Identity3Model.create(validIdentity)
    expect(model._doc).to.deep.include(validIdentity)
  })
})
