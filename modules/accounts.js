var crypto = require('crypto');
var	bignum = require('../helpers/bignum.js');
var	ed = require('ed25519');
var	slots = require('../helpers/slots.js');
var	Router = require('../helpers/router.js');
var	util = require('util');
var	constants = require('../helpers/constants.js');
var	TransactionTypes = require('../helpers/transaction-types.js');
var	Diff = require('../helpers/diff.js');
var	util = require('util');
var	extend = require('extend');
var Cryptr = require('cryptr');
var	sandboxHelper = require('../helpers/sandbox.js');

// private fields
var modules, library, self, privated = {}, shared = {};


// Constructor
function Accounts(cb, scope) {
	library = scope;
	self = this;
	self.__private = privated;
	privated.attachApi();

	setImmediate(cb, null, self);
}

// private methods
privated.attachApi = function () {
	var router = new Router();

	router.use(function (req, res, next) {
		if (modules) return next();
		res.status(500).send({success: false, error: "Blockchain is loading"});
	});

	router.map(shared, {
		"post /walletaddress": "binding",
		"get /getBalance": "getBalance",
		"post /getKeypair": "getKeypair",
		"get /user/get": "getUser",
		"get /": "getAccount",
		"post /getsign": "getsign",
		"post /getverify": "getverify",
	});

	if (process.env.DEBUG && process.env.DEBUG.toUpperCase() == "TRUE") {
		router.get('/getAllAccounts', function (req, res) {
			return res.json({success: true, accounts: privated.accounts});
		});
	}

	if (process.env.TOP && process.env.TOP.toUpperCase() == "TRUE") {
		router.get('/top', function (req, res, next) {
			req.sanitize(req.query, {
				type: "object",
				properties: {
					limit: {
						type: "integer",
						minimum: 0,
						maximum: 100
					},
					offset: {
						type: "integer",
						minimum: 0
					}
				}
			}, function (err, report, query) {
				if (err) return next(err);
				if (!report.isValid) return res.json({success: false, error: report.issues});
				self.getAccounts({
					sort: {
						balance: -1
					},
					offset: query.offset,
					limit: query.limit
				}, function (err, raw) {
					if (err) {
						return res.json({success: false, error: err.toString()});
					}
					var accounts = raw.map(function (fullAccount) {
						return {
							address: fullAccount.address,
							username: fullAccount.username,
							balance: fullAccount.balance,
							publicKey: fullAccount.publicKey
						};
					});

					res.json({success: true, accounts: accounts});
				});
			});
		});
	}

	router.get('/count', function (req, res) {
		return res.json({success: true, count: Object.keys(privated.accounts).length});
	});

	router.use(function (req, res, next) {
		res.status(500).send({success: false, error: "API endpoint was not found"});
	});

	library.network.app.use('/api/accounts', router);
	library.network.app.use(function (err, req, res, next) {
		if (!err) return next();
		library.logger.error(req.url, err.toString());
		res.status(500).send({success: false, error: err.toString()});
	});
};

privated.openAccount = function (secret, cb) {
	var hash = crypto.createHash('sha256').update(secret, 'utf8').digest();
	var keypair = ed.MakeKeypair(hash);

	self.setAccountAndGet({publicKey: keypair.publicKey.toString('hex')}, cb);
};

// 生成公钥
Accounts.prototype.generateAddressByPublicKey = function (publicKey) {
	var publicKeyHash = crypto.createHash('sha1').update(publicKey, 'hex').digest();
	var hash40 = publicKeyHash.toString('hex');
	var address = hash40 + 'M';
	return address;
};

//根据条件查询账户
Accounts.prototype.getAccount = function (filter, fields, cb) {
	if (filter.publicKey) {
		filter.address = self.generateAddressByPublicKey(filter.publicKey);
		delete filter.publicKey;
	}

	library.logic.account.get(filter, fields, cb);
};

//查询所有账户
Accounts.prototype.getAccounts = function (filter, fields, cb) {
	library.logic.account.getAll(filter, fields, cb);
};

Accounts.prototype.setAccountAndGet = function (data, cb) {
	var address = data.address || null;
	if (address === null) {
		if (data.publicKey) {
			address = self.generateAddressByPublicKey(data.publicKey);
		} else {
			return cb("Missing address or public key");
		}
	}
	if (!address) {
		throw cb("Invalid public key");
	}
	library.logic.account.set(address, data, function (err) {
		if (err) {
			return cb(err);
		}
		library.logic.account.get({address: address}, cb);
	});
};

Accounts.prototype.mergeAccountAndGet = function (data, cb) {
	var address = data.address || null;
	if (address === null) {
		if (data.publicKey) {
			address = self.generateAddressByPublicKey(data.publicKey);
		} else {
			return cb("Missing address or public key");
		}
	}
	if (!address) {
		throw cb("Invalid public key");
	}
	library.logic.account.merge(address, data, cb);
};

Accounts.prototype.sandboxApi = function (call, args, cb) {
	sandboxHelper.callMethod(shared, call, args, cb);
};

// Events
Accounts.prototype.onBind = function (scope) {
	modules = scope;
};

privated.getKey = function (secret) {
	var hash = crypto.createHash('sha256').update(secret, 'utf8').digest();
	var keypairBuff = ed.MakeKeypair(hash);
	var keypair = {};
	keypair.publicKey = keypairBuff.publicKey.toString('hex');
	keypair.privateKey = keypairBuff.privateKey.toString('hex');
	return keypair;
}

shared.binding = function (req, cb) {
	cryptr = new Cryptr('myTotalySecretKey');
	var body = req.body;
	var time = new Date().getTime();
	var salt = Math.round(Math.random() * 1000000000) % 100;
	var str_salt = body.PRIVATE_SECRET + time + salt;
	body.secret = cryptr.encrypt(str_salt);

	library.scheme.validate(body, {
		type: "object",
		properties: {
			LOGIN_NAME: {
				type: "string",
				minLength: 1,
				maxLength: 100
			},
			PRIVATE_SECRET: {
				type: "string",
				minLength: 1,
				maxLength: 100
			}
		},
		required: ["LOGIN_NAME","PRIVATE_SECRET"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}
		library.dbLite.query("select LOGIN_NAME from  mem_accounts where LOGIN_NAME=$LOGIN_NAME",{LOGIN_NAME:body.LOGIN_NAME},["LOGIN_NAME"], function(err,rows){
			if(rows.length==0) {
				privated.openAccount(body.secret, function (err, account) {
					if (!err) {
						var encrypt = cryptr.encrypt(body.secret);
						library.dbLite.query("UPDATE mem_accounts set LOGIN_NAME=$LOGIN_NAME,PRIVATE_SECRET=$PRIVATE_SECRET where address = $address ", {
							LOGIN_NAME: body.LOGIN_NAME,
							PRIVATE_SECRET: encrypt,
							address: account.address
						});
					}
					if (!err) {
						var hash = crypto.createHash('sha256').update(body.secret, 'utf8').digest();
						var keypair = ed.MakeKeypair(hash);
						var PUBLICKEY = keypair.publicKey.toString('hex');
						var data = {
							ADDRESS: account.address,
							PRIVATE_SECRET: body.secret,
							PUBLICKEY: PUBLICKEY
						};
						return cb(null, {USER:data});
					} else {
						return cb(err);
					}
				});
			}else{
				return cb("loginname already generate address");
			}
		});
	});
};

shared.getBalance = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			ADDRESS: {
				type: "string",
				minLength: 1
			}
		},
		required: ["ADDRESS"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		var isAddress = /^[0-9a-z]+[M|m]$/g;
		if (!isAddress.test(query.ADDRESS)) {
			return cb("Invalid address");
		}

		self.getAccount({address: query.ADDRESS}, function (err, account) {
			if (err) {
				return cb(err.toString());
			}
			var balance = account ? account.balance : 0;

			cb(null, {balance: balance});
		});
	});
};

shared.getKeypair = function (req, cb) {
	var body = req.body;
	library.scheme.validate(body, {
		type: "object",
		properties: {
			SECRET: {
				type: "string",
				minLength: 1
			}
		},
		required: ["SECRET"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}
		var KEYPAIR = privated.getKey(body.SECRET)
		cb(null, {KEYPAIR: KEYPAIR});
	});
};

shared.getAccount = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			address: {
				type: "string",
				minLength: 1
			}
		},
		required: ["address"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		self.getAccount({address: query.address}, function (err, account) {
			if (err) {
				return cb(err.toString());
			}
			if (!account) {
				return cb("Account not found");
			}

			cb(null, {
				account: {
					address: account.address,
					username: account.username,
					unconfirmedBalance: account.u_balance,
					balance: account.balance,
					publicKey: account.publicKey,
					unconfirmedSignature: account.u_secondSignature,
					secondSignature: account.secondSignature,
					secondPublicKey: account.secondPublicKey,
					multisignatures: account.multisignatures,
					u_multisignatures: account.u_multisignatures
				}
			});
		});
	});
};

shared.getUser = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			LOGIN_NAME: {
				type: "string",
				minLength: 1
			},
			ADDRESS: {
				type: "string",
				minLength: 1
			}
		}
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}
		var where = [];
		var params = {};

		if (query.LOGIN_NAME) {
			params.LOGIN_NAME = query.LOGIN_NAME;
			where.push("LOGIN_NAME = $LOGIN_NAME");
		}

		if (query.ADDRESS) {
			params.ADDRESS = query.ADDRESS;
			where.push("address = $ADDRESS");
		}

		if (query.start !== null) {
			params.start = query.start;
		}

		if (query.limit !== null) {
			if (query.limit > 100) {
				return cb("Invalid limit. Maximum is 100");
			}
			params.limit = query.limit;
		}

		where.push('LOGIN_NAME  != ""');

		library.dbLite.query("SELECT LOGIN_NAME,address,lower(hex(publicKey)) FROM mem_accounts" +
			(where.length ? (' where ' + where.join(' and ')) : '') + " " +
			(params.start ? ' offset $start' : '') +
			(params.limit ? ' limit $limit ' : ''),
			params, ['LOGIN_NAME', 'ADDRESS', 'PUBLICKEY'], function (err, rows) {
				var users = rows;
				library.dbLite.query("select LOGIN_NAME from mem_accounts" +
					(where.length ? (' where ' + where.join(' and ')) : ''),
					params, ['LOGIN_NAME'], function (err, rows) {
						TOTAL = rows.length;
						cb(null, {USERS: users, TOTAL: TOTAL});
					});
			});
	});
};


shared.getsign = function (req, cb) {
	var body = req.body;
	library.scheme.validate(body, {
		type: "object",
		properties: {
			SECRET: {
				type: "string",
				minLength: 1
			}
		}
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		var hash = crypto.createHash('sha256').update(body.SECRET, 'utf8').digest();
		var keypair = ed.MakeKeypair(hash);
		var bytes = privated.getBytes(body.ASSET);
		var hash = crypto.createHash('sha256').update(bytes).digest();
		var sign=ed.Sign(hash, keypair).toString('hex');
		cb(null,{SIGN:sign});
	});
};

shared.getverify = function (req, cb) {
	var body = req.body;
	library.scheme.validate(body, {
		type: "object",
		properties: {
			SECRET: {
				type: "string",
				minLength: 1
			}
		}
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}
		var remove = 64;

		try {
			var data = privated.getBytes(body.ASSET);
			var hash = crypto.createHash('sha256').update(data).digest();

			var keyhash = crypto.createHash('sha256').update(body.SECRET, 'utf8').digest();
			var keypair = ed.MakeKeypair(keyhash);
			var publickey=keypair.publicKey.toString('hex');

			var SignatureBuffer = new Buffer(body.SIGN, 'hex');
			var PublicKeyBuffer = new Buffer(publickey,'hex');
			var res = ed.Verify(hash, SignatureBuffer || ' ', PublicKeyBuffer || ' ');
		} catch (e) {
			throw Error(e.toString());
		}
		cb(null,{RES:res});
	});
};

privated.getBytes = function (sign) {
	var size = 4 + 4 + 8 + 4 + 4 + 8 + 8 + 4 + 4 + 4 + 32 + 32 + 64;

	try {
		var bb = new ByteBuffer(size, true);
		bb.writeUTF8String(sign);
		bb.flip();
		var b = bb.toBuffer();
	} catch (e) {
		throw Error(e.toString());
	}

	return b;
};

// Export
module.exports = Accounts;
