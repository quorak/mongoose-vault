require('dotenv').config()
const expect = require('chai').expect
const mongoose = require('mongoose')
const nodeVault = require('node-vault')
const mongooseVault = require('./mongoose-vault')

Schema = mongoose.Schema

let vault
before(async () => {
  mongoose.connect(process.env.MONGO_CONNECTION_STRING, {useNewUrlParser: true})
  vault = await nodeVault({endpoint: process.env.VAULT_CONNECTION_STRING, token: process.env.VAULT_DEV_ROOT_TOKEN_ID})
  try {
    await vault.mount({mount_point: 'transit', type: 'transit'})
  } catch (e) { /* Already mounted */ }

  if (mongoose.connection.collections['identities']) {
    mongoose.connection.collections['identities'].drop(function (err) {
      console.log('collection dropped')
    })
  }
})

var validIdentity = {
  'firstName': 'Max',
  'lastName': 'Mustermann',
  'address': 'Karlstr. 1',
  'email': 'test@test.de'
}

describe('Test Mongoose Vault with convergentEncryption disabled', function () {
  // Setup Mongose Schema and Model
  var Identity = new Schema({
    firstName: { type: String, required: true},
    lastName: { type: String, required: true},
    address: { type: String },
    address2: { type: String },
    email: { type: String }
  })

  Identity.plugin(mongooseVault, {
    middleware: true,
    decryptPostSave: true,
    keyCreationConvergentEncryption: false
  })

  var IdentityModel = mongoose.model('Identity', Identity)

  before(async () => {
    IdentityModel.connectVault(vault)
  })

  it('Mongoose create should encrypt and decrypt the document.', async function () {
    let model = await IdentityModel.create(validIdentity)
    expect(model).to.deep.include(validIdentity)
  })

  it('Mongoose encrypt should not include the plaintext Field', async function () {
    let model = new IdentityModel(validIdentity)
    expect(model).to.include(validIdentity)
    await model.encrypt()
    expect(model).to.not.include(validIdentity)
  })

  it('Mongoose findOne should decrypt', async function () {
    let model = await IdentityModel.create(validIdentity)
    expect(model).to.deep.include(validIdentity)

    let modelNew = await IdentityModel.findById(model.id)
    expect(modelNew).to.include(validIdentity)
  })

  it('Mongoose findById should decrypt', async function () {
    let models = await IdentityModel.find({})
    expect(models).to.be.an('array')
    expect(models).to.have.lengthOf.at.least(2)
    expect(models[0]).to.include(validIdentity)
  })

  it('Mongoose find by encrypted field should not return any', async function () {
    let models = await IdentityModel.find({firstName: 'Max'})
    expect(models).to.be.an('array')
    expect(models).to.have.lengthOf(0)
  })
})

describe('Test Mongoose Vault with convergentEncryption enabled', function () {
  // Setup Mongose Schema and Model
  var Identity2 = new Schema({
    firstName: { type: String, required: true},
    lastName: { type: String, required: true},
    address: { type: String },
    address2: { type: String },
    email: { type: String }
  })

  Identity2.plugin(mongooseVault, {
    middleware: true,
    decryptPostSave: true,
    // THIS WILL ENABLE SEARCH TO WORK
    keyCreationConvergentEncryption: true
  })

  var Identity2Model = mongoose.model('Identity2', Identity2)

  before(async () => {
    Identity2Model.connectVault(vault)
  })

  it('Mongoose find by encrypted fields should return matching documents', async function () {
    let model = await Identity2Model.create(validIdentity)
    expect(model).to.deep.include(validIdentity)
    let models = await Identity2Model.find({firstName: 'Max'})
    expect(models).to.be.an('array')
    expect(models).to.have.lengthOf.at.least(1)
    expect(models[0]).to.include(validIdentity)
  })
})

describe('Test Mongoose Vault with keyName per_document', function () {
  // Setup Mongose Schema and Model
  var Identity3 = new Schema({
    firstName: { type: String, required: true},
    lastName: { type: String, required: true},
    address: { type: String },
    address2: { type: String },
    email: { type: String }
  })

  Identity3.plugin(mongooseVault, {
    middleware: true,
    decryptPostSave: true,
    keyCreationConvergentEncryption: true,
    keyName: 'per_document'
  })

  var Identity3Model = mongoose.model('Identity3', Identity3)

  before(async () => {
    Identity3Model.connectVault(vault)
  })

  it('Mongoose create should encrypt and decrypt the document.', async function () {
    let model = await Identity3Model.create(validIdentity)
    expect(model).to.deep.include(validIdentity)
  })
})
