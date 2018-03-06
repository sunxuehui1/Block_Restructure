var ed = require('ed25519'),
	util = require('util'),
	ByteBuffer = require("bytebuffer"),
	crypto = require('crypto'),
	genesisblock = null,
	constants = require("../helpers/constants.js"),
	slots = require('../helpers/slots.js'),
	extend = require('extend'),
	Router = require('../helpers/router.js'),
	async = require('async'),
	TransactionTypes = require('../helpers/transaction-types.js'),
	sandboxHelper = require('../helpers/sandbox.js');

// private fields
var modules, library, self, privated = {}, shared = {};

privated.hiddenTransactions = [];
privated.unconfirmedTransactions = [];
privated.unconfirmedTransactionsIdIndex = {};
privated.doubleSpendingTransactions = {};

function Transfer() {
	this.create = function (data, trs) {
		trs.recipientId = data.recipientId;
		trs.recipientUsername = data.recipientUsername;
		trs.amount = data.amount;

		return trs;
	}

	this.calculateFee = function (trs, sender) {
		return library.logic.block.calculateFee();
	}

	this.verify = function (trs, sender, cb) {
		var isAddress = /^[0-9a-z]+[M|m]$/g;
		if (!isAddress.test(trs.recipientId.toLowerCase())) {
			return cb("Invalid recipient");
		}

		if (trs.amount <= 0) {
			return cb("Invalid transaction amount");
		}

		cb(null, trs);
	}

	this.process = function (trs, sender, cb) {
		setImmediate(cb, null, trs);
	}

	this.getBytes = function (trs) {
		return null;
	}

	this.apply = function (trs, block, sender, cb) {
		modules.accounts.setAccountAndGet({address: trs.recipientId}, function (err, recipient) {
			if (err) {
				return cb(err);
			}

			modules.accounts.mergeAccountAndGet({
				address: trs.recipientId,
				balance: trs.amount,
				u_balance: trs.amount,
				blockId: block.id,
				round: modules.round.calc(block.height)
			}, function (err) {
				cb(err);
			});
		});
	}

	this.undo = function (trs, block, sender, cb) {
		modules.accounts.setAccountAndGet({address: trs.recipientId}, function (err, recipient) {
			if (err) {
				return cb(err);
			}

			modules.accounts.mergeAccountAndGet({
				address: trs.recipientId,
				balance: -trs.amount,
				u_balance: -trs.amount,
				blockId: block.id,
				round: modules.round.calc(block.height)
			}, function (err) {
				cb(err);
			});
		});
	}

	this.applyUnconfirmed = function (trs, sender, cb) {
		setImmediate(cb);
	}

	this.undoUnconfirmed = function (trs, sender, cb) {
		setImmediate(cb);
	}

	this.objectNormalize = function (trs) {
		delete trs.blockId;
		return trs;
	}

	this.dbRead = function (raw) {
		return null;
	}

	this.dbSave = function (trs, cb) {
		setImmediate(cb);
	}

	this.ready = function (trs, sender) {
		if (sender.multisignatures.length) {
			if (!trs.signatures) {
				return false;
			}

			return trs.signatures.length >= sender.multimin - 1;
		} else {
			return true;
		}
	}
}

// Constructor
function Transactions(cb, scope) {
	library = scope;
	genesisblock = library.genesisblock;
	self = this;
	self.__private = privated;
	privated.attachApi();

	library.logic.transaction.attachAssetType(TransactionTypes.SEND, new Transfer());

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
		"get /": "getTransactions",
		"post /": "addTransactions"
	});

	router.use(function (req, res, next) {
		res.status(500).send({success: false, error: "API endpoint not found"});
	});

	library.network.app.use('/api/transactions', router);
	library.network.app.use(function (err, req, res, next) {
		if (!err) return next();
		library.logger.error(req.url, err.toString());
		res.status(500).send({success: false, error: err.toString()});
	});
}

privated.list = function (filter, cb) {
	var params = {}, fields_where = [];
	if (filter.TRS_ID) {
		fields_where.push('id = $TRS_ID');
		params.TRS_ID = filter.TRS_ID;
	}
	if (filter.BLOCK_ID) {
		fields_where.push('blockId = $BLOCK_ID');
		params.BLOCK_ID = filter.BLOCK_ID;
	}
	if (filter.SENDER_PUBLICKEY) {
		fields_where.push('lower(hex(senderPublicKey)) = $SENDER_PUBLICKEY')
		params.SENDER_PUBLICKEY = filter.SENDER_PUBLICKEY;
	}
	if (filter.SENDER_ID) {
		fields_where.push('senderId = $SENDER_ID');
		params.SENDER_ID = filter.SENDER_ID;
	}
	if (filter.RECIPIENT_ID) {
		fields_where.push('recipientId = $RECIPIENT_ID')
		params.RECIPIENT_ID = filter.RECIPIENT_ID;
	}
	if (filter.AMOUNT >= 0) {
		fields_where.push('amount = $AMOUNT');
		params.AMOUNT = filter.AMOUNT;
	}

	if (filter.start !== null) {
		params.start = filter.start;
	}

	if (filter.limit !== null) {
		if (filter.limit > 100) {
			return cb("Invalid limit. Maximum is 100");
		}
		params.limit = filter.limit;
	}
	 


	library.dbLite.query("SELECT id,blockId,type,timestamp,senderId,recipientId,amount FROM trs" + 
	(fields_where.length ? (' where ' + fields_where.join(' and ')) : '') + " " +
	(params.start ? ' offset $start' : '') +
	(params.limit ? ' limit $limit ' : ''),
	params,['ID','BLOCK_ID','TYPE','TIMESTAMP','SENDER_ID','RECIPIENT_ID','AMOUNT'], function (err, rows) {
				var data = {};
				data.transactions = rows;
				library.dbLite.query("select id from trs" + 
				(fields_where.length ? (' where ' + fields_where.join(' and ')) : ''),
				params, ['id'], function (err, rows) {
					data.count = rows.length;
					cb(null, data);
				});
		});
	}


privated.addUnconfirmedTransaction = function (transaction, sender, cb) {
	self.applyUnconfirmed(transaction, sender, function (err) {
		if (err) {
			self.addDoubleSpending(transaction);
			return setImmediate(cb, err);
		}

		privated.unconfirmedTransactions.push(transaction);
		var index = privated.unconfirmedTransactions.length - 1;
		privated.unconfirmedTransactionsIdIndex[transaction.id] = index;

		setImmediate(cb);
	});
}

// Public methods
Transactions.prototype.getUnconfirmedTransaction = function (id) {
	var index = privated.unconfirmedTransactionsIdIndex[id];
	return privated.unconfirmedTransactions[index];
}

Transactions.prototype.addDoubleSpending = function (transaction) {
	privated.doubleSpendingTransactions[transaction.id] = transaction;
}

Transactions.prototype.pushHiddenTransaction = function (transaction) {
	privated.hiddenTransactions.push(transaction);
}

Transactions.prototype.shiftHiddenTransaction = function () {
	return privated.hiddenTransactions.shift();
}

Transactions.prototype.deleteHiddenTransaction = function () {
	privated.hiddenTransactions = [];
}

Transactions.prototype.getUnconfirmedTransactionList = function (reverse) {
	var a = [];
	for (var i = 0; i < privated.unconfirmedTransactions.length; i++) {
		if (privated.unconfirmedTransactions[i] !== false) {
			a.push(privated.unconfirmedTransactions[i]);
		}
	}

	return reverse ? a.reverse() : a;
}

Transactions.prototype.removeUnconfirmedTransaction = function (id) {
	var index = privated.unconfirmedTransactionsIdIndex[id];
	delete privated.unconfirmedTransactionsIdIndex[id];
	privated.unconfirmedTransactions[index] = false;
}

Transactions.prototype.processUnconfirmedTransaction = function (transaction, broadcast, cb) {
	modules.accounts.setAccountAndGet({publicKey: transaction.senderPublicKey}, function (err, sender) {
		function done(err) {
			if (err) {
				return cb(err);
			}
           //加入区块链
			privated.addUnconfirmedTransaction(transaction, sender, function (err) {
				if (err) {
					return cb(err);
				}

				library.bus.message('unconfirmedTransaction', transaction, broadcast);

				cb();
			});
		}

		if (err) {
			return done(err);
		}

		if (transaction.requesterPublicKey && sender && sender.multisignatures && sender.multisignatures.length) {
			modules.accounts.getAccount({publicKey: transaction.requesterPublicKey}, function (err, requester) {
				if (err) {
					return done(err);
				}

				if (!requester) {
					return cb("Invalid requester");
				}

				library.logic.transaction.process(transaction, sender, requester, function (err, transaction) {
					if (err) {
						return done(err);
					}

					// Check in confirmed transactions
					if (privated.unconfirmedTransactionsIdIndex[transaction.id] !== undefined || privated.doubleSpendingTransactions[transaction.id]) {
						return cb("Transaction already exists");
					}

					library.logic.transaction.verify(transaction, sender, done);
				});
			});
		} else {
			library.logic.transaction.process(transaction, sender, function (err, transaction) {
				if (err) {
					return done(err);
				}

				// Check in confirmed transactions
				if (privated.unconfirmedTransactionsIdIndex[transaction.id] !== undefined || privated.doubleSpendingTransactions[transaction.id]) {
					return cb("Transaction already exists");
				}

				library.logic.transaction.verify(transaction, sender, done);
			});
		}
	});
}

Transactions.prototype.applyUnconfirmedList = function (ids, cb) {
	async.eachSeries(ids, function (id, cb) {
		var transaction = self.getUnconfirmedTransaction(id);
		modules.accounts.setAccountAndGet({publicKey: transaction.senderPublicKey}, function (err, sender) {
			if (err) {
				self.removeUnconfirmedTransaction(id);
				self.addDoubleSpending(transaction);
				return setImmediate(cb);
			}
			self.applyUnconfirmed(transaction, sender, function (err) {
				if (err) {
					self.removeUnconfirmedTransaction(id);
					self.addDoubleSpending(transaction);
				}
				setImmediate(cb);
			});
		});
	}, cb);
}

Transactions.prototype.undoUnconfirmedList = function (cb) {
	var ids = [];
	async.eachSeries(privated.unconfirmedTransactions, function (transaction, cb) {
		if (transaction !== false) {
			ids.push(transaction.id);
			self.undoUnconfirmed(transaction, cb);
		} else {
			setImmediate(cb);
		}
	}, function (err) {
		cb(err, ids);
	})
}

Transactions.prototype.apply = function (transaction, block, sender, cb) {
	library.logic.transaction.apply(transaction, block, sender, cb);
}

Transactions.prototype.undo = function (transaction, block, sender, cb) {
	library.logic.transaction.undo(transaction, block, sender, cb);
}

Transactions.prototype.applyUnconfirmed = function (transaction, sender, cb) {
	if (!sender && transaction.blockId != genesisblock.block.id) {
		return cb("Invalid account");
	} else {
		if (transaction.requesterPublicKey) {
			modules.accounts.getAccount({publicKey: transaction.requesterPublicKey}, function (err, requester) {
				if (err) {
					return cb(err);
				}

				if (!requester) {
					return cb("Invalid requester");
				}

				library.logic.transaction.applyUnconfirmed(transaction, sender, requester, cb);
			});
		} else {
			library.logic.transaction.applyUnconfirmed(transaction, sender, cb);
		}
	}
}

Transactions.prototype.undoUnconfirmed = function (transaction, cb) {
	modules.accounts.getAccount({publicKey: transaction.senderPublicKey}, function (err, sender) {
		if (err) {
			return cb(err);
		}
		library.logic.transaction.undoUnconfirmed(transaction, sender, cb);
	});
}

Transactions.prototype.receiveTransactions = function (transactions, cb) {
	async.eachSeries(transactions, function (transaction, cb) {
		self.processUnconfirmedTransaction(transaction, true, cb);
	}, function (err) {
		cb(err, transactions);
	});
}

Transactions.prototype.sandboxApi = function (call, args, cb) {
	sandboxHelper.callMethod(shared, call, args, cb);
}

// Events
Transactions.prototype.onBind = function (scope) {
	modules = scope;
}

// Shared
shared.getTransactions = function (req, cb) {
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			TRS_ID: {
				type: "string"
			},
			BLOCK_ID: {
				type: "string"
			},
			SENDER_PUBLICKEY: {
				type: "string",
				format: "publicKey"
			},
			SENDER_ID: {
				type: "string"
			},
			RECIPIENT_ID: {
				type: "string"
			},
			AMOUNT: {
				type: "integer",
				minimum: 0,
				maximum: constants.fixedPoint
			},
			start: {
				type: "integer",
				minimum: 0,
				maximum: 100
			},
			limit: {
				type: "integer",
				minimum: 0
			}
		}
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		privated.list(query, function (err, data) {
			if (err) {
				return cb("Failed to get transactions");
			}

			cb(null, {TRANSACTIONS: data.transactions, TOTAL: data.count});
		});
	});
}


shared.addTransactions = function (req, cb) {
	var body = req.body;
	library.scheme.validate(body, {
		type: "object",
		properties: {
			SECRET: {
				type: "string",
				minLength: 1,
				maxLength: 100
			},
			AMOUNT: {
				type: "integer",
				minimum: 1,
				maximum: constants.totalAmount
			},
			RECIPIENT_ID: {
				type: "string",
				minLength: 1
			},
			PUBLICKEY: {
				type: "string",
				format: "publicKey"
			},
			SECONDSECRET: {
				type: "string",
				minLength: 1,
				maxLength: 100
			},
			MULTISIG_ACCOUNT_PUBLICKEY: {
				type: "string",
				format: "publicKey"
			}
		},
		required: ["SECRET", "AMOUNT", "RECIPIENT_ID"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		var hash = crypto.createHash('sha256').update(body.SECRET, 'utf8').digest();
		var keypair = ed.MakeKeypair(hash);

		//验证密码
		if (body.PUBLICKEY) {
			if (keypair.publicKey.toString('hex') != body.PUBLICKEY) {
				return cb("Invalid passphrase");
			}
		}

		var query = {};

		//验证接收方地址格式
		var isAddress = /^[0-9a-z]+[M|m]$/g;
		if (isAddress.test(body.RECIPIENT_ID)) {
			query.address = body.RECIPIENT_ID;
		} else {
			query.username = body.RECIPIENT_ID;
		}

		library.balancesSequence.add(function (cb) {
			modules.accounts.getAccount(query, function (err, recipient) {
				if (err) {
					return cb(err.toString());
				}
				if (!recipient && query.username) {
					return cb("Recipient not found");
				}
				var recipientId = recipient ? recipient.address : body.recipientId;
				var recipientUsername = recipient ? recipient.username : null;

				if (body.MULTISIG_ACCOUNT_PUBLICKEY && body.MULTISIG_ACCOUNT_PUBLICKEY != keypair.publicKey.toString('hex')) {
					modules.accounts.getAccount({publicKey: body.MULTISIG_ACCOUNT_PUBLICKEY}, function (err, account) {
						if (err) {
							return cb(err.toString());
						}

						if (!account || !account.publicKey) {
							return cb("Multisignature account not found");
						}

						if (!account || !account.multisignatures) {
							return cb("Account does not have multisignatures enabled");
						}

						if (account.multisignatures.indexOf(keypair.publicKey.toString('hex')) < 0) {
							return cb("Account does not belong to multisignature group");
						}

						modules.accounts.getAccount({publicKey: keypair.publicKey}, function (err, requester) {
							if (err) {
								return cb(err.toString());
							}

							if (!requester || !requester.publicKey) {
								return cb("Invalid requester");
							}

							if (requester.secondSignature && !body.SECONDSECRET) {
								return cb("Invalid second passphrase");
							}

							if (requester.publicKey == account.publicKey) {
								return cb("Invalid requester");
							}

							var secondKeypair = null;

							if (requester.secondSignature) {
								var secondHash = crypto.createHash('sha256').update(body.SECONDSECRET, 'utf8').digest();
								secondKeypair = ed.MakeKeypair(secondHash);
							}

							try {
								var transaction = library.logic.transaction.create({
									type: TransactionTypes.SEND,
									amount: body.AMOUNT,
									sender: account,
									recipientId: recipientId,
									recipientUsername: recipientUsername,
									keypair: keypair,
									requester: keypair,
									secondKeypair: secondKeypair
								});
							} catch (e) {
								return cb(e.toString());
							}
							modules.transactions.receiveTransactions([transaction], cb);
						});
					});
				} else {
					modules.accounts.getAccount({publicKey: keypair.publicKey.toString('hex')}, function (err, account) {
						if (err) {
							return cb(err.toString());
						}
						if (!account || !account.publicKey) {
							return cb("Invalid account");
						}

						if (account.secondSignature && !body.SECONDSECRET) {
							return cb("Invalid second passphrase");
						}

						var secondKeypair = null;

						if (account.secondSignature) {
							var secondHash = crypto.createHash('sha256').update(body.SECONDSECRET, 'utf8').digest();
							secondKeypair = ed.MakeKeypair(secondHash);
						}

						try {
							var transaction = library.logic.transaction.create({
								type: TransactionTypes.SEND,
								amount: body.AMOUNT,
								sender: account,
								recipientId: recipientId,
								recipientUsername: recipientUsername,
								keypair: keypair,
								secondKeypair: secondKeypair
							});
						} catch (e) {
							return cb(e.toString());
						}
						modules.transactions.receiveTransactions([transaction], cb);
					});
				}
			});
		}, function (err, transaction) {
			if (err) {
				return cb(err.toString());
			}

			cb(null, {transactionId: transaction[0].id});
		});
	});
}

// Export
module.exports = Transactions;
