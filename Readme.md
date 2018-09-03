[![Build Status](https://travis-ci.org/quorak/mongoose-vault.svg?branch=master)](https://travis-ci.org/quorak/mongoose-vault)

#mongoose-vault
==================

Simple encryption plugin for Mongoose, using the [transit](https://www.vaultproject.io/docs/secrets/transit/index.html) backend from [Hasicorp's Vault](https://www.vaultproject.io/) (Encryption as a Service) ([API](https://www.vaultproject.io/api/secret/transit/index.html)).

Heavily inspired by [mongoose-encryption](https://github.com/joegoldbeck/mongoose-encryption) plugin

## Before You Get Started

Read the [Security Notes](#security-notes) below.

Encryption is only supported on fields of type String. Please file a FeatureRequest if you wish support for more Types.

### Key Name

The scope of the encryption key can be `per_collection`, `per_document` or completely static. Vault will create a new key, if the specified name does not exist.

### Searches     on encrypted fields

In Order to enable searches on encrypted fields, we can enable vaults [convergent_encryption](https://www.vaultproject.io/docs/secrets/transit/index.html) 
on the used keys. This will only work on the subset that is encrypted same key. e.g. `keyName: per_collection` will work `keyName: per_document` will not  

## Installation

`npm install mongoose-vault`

### Basic

By default, all fields are encrypted except for `_id`, `__v`, and fields with indexes

```javascript
var mongoose = require('mongoose');
var encrypt = require('mongoose-vault');
var nodeVault = require('node-vault');

var userSchema = new mongoose.Schema({
    name: String,
    age: Number
    // whatever else
});

userSchema.plugin(encrypt, {
  encryptedFields: ['name','age'], // A list of fields to encrypt. Default is to encrypt all fields.
  excludeFromEncryption: [],  //A list of fields to not encrypt
  decryptPostSave: true, // Whether to automatically decrypt documents in the application after saving them (faster if false)
  keyName: 'per_collection', // If you update the Model name of the schema, this should be set to its original name
  keyCreationKeyType: "aes256-gcm96", // This can be set when encryption key is expected to be created. See https://www.vaultproject.io/api/secret/transit/index.html#type-1
  keyCreationConvergentEncryption: false // Needs to be true if the key is expected to be created and findByEncryptedField should be supported. see https://www.vaultproject.io/api/secret/transit/index.html#convergent_encryption-1
 });

User = mongoose.model('User', userSchema);

// Initialize the vault
let vault = nodeVault({endpoint: process.env.VAULT_CONNECTION_STRING, token: process.env.VAULT_DEV_ROOT_TOKEN_ID})

// connect vault to the model
User.connectVault(vault)

// Create transit backend in vault
vault.mount({mount_point: 'transit',type: 'transit'})

User.create({name:"Max"})
...
```

## Development and Testing

Setup Hashicorp Vault and Mongo
```bash
docker run --rm --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=insecureRootTestingToken' -p8200:8200 vault
docker run --rm -27017:27017 mongo
```


## Security Issue Reporting / Disclaimer

None of the authors are security experts. We relied on accepted tools and practices, and tried hard to make this tool solid and well-tested, but nobody's perfect. Please look over the code carefully before using it (and note the legal disclaimer below). **If you find or suspect any security-related issues, please email us** and we will get right on it. For non-security-related issues, please open a Github issue or pull request.
Copyright @ [mongoose-encryption](https://github.com/joegoldbeck/mongoose-encryption)