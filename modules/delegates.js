var crypto = require('crypto');
var	extend = require('extend');
var	ed = require('ed25519');
var	async = require('async');
var	shuffle = require('knuth-shuffle').knuthShuffle;
var	Router = require('../helpers/router.js');
var	slots = require('../helpers/slots.js');
var	schedule = require('node-schedule');
var	util = require('util');
var	Diff = require('../helpers/diff.js');
var	constants = require('../helpers/constants.js');
var	TransactionTypes = require('../helpers/transaction-types.js');
var	sandboxHelper = require('../helpers/sandbox.js');

require('array.prototype.find'); // Old node fix

// private fields
var modules, library, self, privated = {}, shared = {};

privated.loaded = false;

privated.keypairs = {};

function Delegate() {
	this.create = function (data, trs) {
		trs.recipientId = null;
		trs.amount = 0;
		trs.asset.delegate = {
			username: data.username || data.sender.username,
			publicKey: data.sender.publicKey
		};

		return trs;
	};

	this.calculateFee = function (trs, sender) {
		return 0;
	};

	this.verify = function (trs, sender, cb) {
		if (trs.recipientId) {
			return setImmediate(cb, "Invalid recipient");
		}

		if (trs.amount !== 0) {
			return setImmediate(cb, "Invalid transaction amount");
		}

		if (!sender.username) {
			if (!trs.asset.delegate.username) {
				return setImmediate(cb, "Invalid transaction asset");
			}

			var allowSymbols = /^[a-z0-9!@$&_.]+$/g;
			if (!allowSymbols.test(trs.asset.delegate.username.toLowerCase())) {
				return setImmediate(cb, "Username contains invalid characters");
			}

			var isAddress = /^[0-9a-z]+[M|m]$/g;
			if (isAddress.test(trs.asset.delegate.username)) {
				return setImmediate(cb, "Username cannot be a potential address");
			}

			if (trs.asset.delegate.username.length < 1) {
				return setImmediate(cb, "Username is too short. Minimum is 1 character");
			}

			if (trs.asset.delegate.username.length > 20) {
				return setImmediate(cb, "Username is too long. Maximum is 20 characters");
			}
		} else {
			if (trs.asset.delegate.username && trs.asset.delegate.username != sender.username) {
				return cb("Account already has a username");
			}
		}

		if (sender.isDelegate) {
			return cb("Account is already a delegate");
		}

		if (sender.username) {
			return cb(null, trs);
		}

		modules.accounts.getAccount({
			username: trs.asset.delegate.username
		}, function (err, account) {
			if (err) {
				return cb(err);
			}

			if (account) {
				return cb("Username already exists");
			}

			cb(null, trs);
		});
	};

	this.process = function (trs, sender, cb) {
		setImmediate(cb, null, trs);
	};

	this.getBytes = function (trs) {
		if (!trs.asset.delegate.username) {
			return null;
		}
		try {
			var buf = new Buffer(trs.asset.delegate.username, 'utf8');
		} catch (e) {
			throw Error(e.toString());
		}

		return buf;
	};

	this.apply = function (trs, block, sender, cb) {
		var data = {
			address: sender.address,
			u_isDelegate: 0,
			isDelegate: 1,
			vote: 0
		};

		if (!sender.nameexist && trs.asset.delegate.username) {
			data.u_username = null;
			data.username = trs.asset.delegate.username;
		}

		modules.accounts.setAccountAndGet(data, cb);
	};

	this.undo = function (trs, block, sender, cb) {
		var data = {
			address: sender.address,
			u_isDelegate: 1,
			isDelegate: 0,
			vote: 0
		};

		if (!sender.nameexist && trs.asset.delegate.username) {
			data.username = null;
			data.u_username = trs.asset.delegate.username;
		}

		modules.accounts.setAccountAndGet(data, cb);
	};

	this.applyUnconfirmed = function (trs, sender, cb) {
		if (sender.u_username && trs.asset.delegate.username && trs.asset.delegate.username != sender.u_username) {
			return cb("Account already has a username");
		}

		if (sender.u_isDelegate) {
			return cb("Account is already a delegate");
		}

		function done() {
			var data = {
				address: sender.address,
				u_isDelegate: 1,
				isDelegate: 0
			};

			if (!sender.nameexist && trs.asset.delegate.username) {
				data.username = null;
				data.u_username = trs.asset.delegate.username;
			}

			modules.accounts.setAccountAndGet(data, cb);
		}

		if (sender.username) {
			return done();
		}

		modules.accounts.getAccount({
			u_username: trs.asset.delegate.username
		}, function (err, account) {
			if (err) {
				return cb(err);
			}

			if (account) {
				return cb("Username already exists");
			}

			done();
		});
	};

	this.undoUnconfirmed = function (trs, sender, cb) {
		var data = {
			address: sender.address,
			u_isDelegate: 0,
			isDelegate: 0
		};

		if (!sender.nameexist && trs.asset.delegate.username) {
			data.username = null;
			data.u_username = null;
		}

		modules.accounts.setAccountAndGet(data, cb);
	};

	this.objectNormalize = function (trs) {
		var report = library.scheme.validate(trs.asset.delegate, {
			type: "object",
			properties: {
				publicKey: {
					type: "string",
					format: "publicKey"
				}
			},
			required: ["publicKey"]
		});

		if (!report) {
			throw Error("Can't verify delegate transaction, incorrect parameters: " + library.scheme.getLastError());
		}

		return trs;
	};

	this.dbRead = function (raw) {
		if (!raw.d_username) {
			return null;
		} else {
			var delegate = {
				username: raw.d_username,
				publicKey: raw.t_senderPublicKey,
				address: raw.t_senderId
			};

			return {delegate: delegate};
		}
	};

	this.dbSave = function (trs, cb) {
		library.dbLite.query("INSERT INTO delegates(username, transactionId) VALUES($username, $transactionId)", {
			username: trs.asset.delegate.username,
			transactionId: trs.id
		}, cb);
	};

	this.ready = function (trs, sender) {
		if (sender.multisignatures.length) {
			if (!trs.signatures) {
				return false;
			}
			return trs.signatures.length >= sender.multimin - 1;
		} else {
			return true;
		}
	};
}

function Vote() {
	this.create = function (data, trs) {
		trs.recipientId = data.sender.address;
		trs.recipientUsername = data.sender.username;
		trs.asset.votes = data.votes.split(',');

		return trs;
	};

	this.calculateFee = function (trs, sender) {
		return 0;
	};

	this.verify = function (trs, sender, cb) {
		if (trs.recipientId != trs.senderId) {
			return setImmediate(cb, "Recipient is identical to sender");
		}

		if (!trs.asset.votes || !trs.asset.votes.length) {
			return setImmediate(cb, "Not enough spare votes available");
		}

		if (trs.asset.votes && trs.asset.votes.length > 33) {
			return setImmediate(cb, "Voting limited exceeded. Maxmium is 33 per transaction");
		}

		modules.delegates.checkDelegates(trs.senderPublicKey, trs.asset.votes, function (err) {
			setImmediate(cb, err, trs);
		});
	};

	this.process = function (trs, sender, cb) {
		setImmediate(cb, null, trs);
	};

	this.getBytes = function (trs) {
		try {
			var buf = trs.asset.votes ? new Buffer(trs.asset.votes.join(''), 'utf8') : null;
		} catch (e) {
			throw Error(e.toString());
		}

		return buf;
	};

	this.apply = function (trs, block, sender, cb) {
		this.scope.account.merge(sender.address, {
			delegates: trs.asset.votes,
			blockId: block.id,
			round: modules.round.calc(block.height)
		}, function (err) {
			cb(err);
		});
	};

	this.undo = function (trs, block, sender, cb) {
		if (trs.asset.votes === null) return cb();

		var votesInvert = Diff.reverse(trs.asset.votes);

		this.scope.account.merge(sender.address, {
			delegates: votesInvert,
			blockId: block.id,
			round: modules.round.calc(block.height)
		}, function (err) {
			cb(err);
		});
	};

	this.applyUnconfirmed = function (trs, sender, cb) {
		modules.delegates.checkUnconfirmedDelegates(trs.senderPublicKey, trs.asset.votes, function (err) {
			if (err) {
				return setImmediate(cb, err);
			}

			this.scope.account.merge(sender.address, {
				u_delegates: trs.asset.votes
			}, function (err) {
				cb(err);
			});
		}.bind(this));
	};

	this.undoUnconfirmed = function (trs, sender, cb) {
		if (trs.asset.votes === null) return cb();

		var votesInvert = Diff.reverse(trs.asset.votes);

		this.scope.account.merge(sender.address, {u_delegates: votesInvert}, function (err) {
			cb(err);
		});
	};

	this.objectNormalize = function (trs) {
		var report = library.scheme.validate(trs.asset, {
			type: "object",
			properties: {
				votes: {
					type: "array",
					minLength: 1,
					maxLength: 105,
					uniqueItems: true
				}
			},
			required: ['votes']
		});

		if (!report) {
			throw new Error("Incorrect votes in transactions: " + library.scheme.getLastError());
		}

		return trs;
	};

	this.dbRead = function (raw) {
		// console.log(raw.v_votes);

		if (!raw.v_votes) {
			return null;
		} else {
			var votes = raw.v_votes.split(',');

			return {votes: votes};
		}
	};

	this.dbSave = function (trs, cb) {
		library.dbLite.query("INSERT INTO votes(votes, transactionId) VALUES($votes, $transactionId)", {
			votes: util.isArray(trs.asset.votes) ? trs.asset.votes.join(',') : null,
			transactionId: trs.id
		}, cb);
	};

	this.ready = function (trs, sender) {
		if (sender.multisignatures.length) {
			if (!trs.signatures) {
				return false;
			}
			return trs.signatures.length >= sender.multimin - 1;
		} else {
			return true;
		}
	};
}

// Constructor
function Delegates(cb, scope) {
	library = scope;
	self = this;
	self.__private = privated;
	privated.attachApi();

	library.logic.transaction.attachAssetType(TransactionTypes.DELEGATE, new Delegate());
	library.logic.transaction.attachAssetType(TransactionTypes.VOTE, new Vote());


	setImmediate(cb, null, self);
}

// private methods
privated.attachApi = function () {
	var router = new Router();

	router.use(function (req, res, next) {
		if (modules && privated.loaded) return next();
		res.status(500).send({success: false, error: "Blockchain is loading"});
	});

	router.map(shared, {
		"post /": "addDelegate",
		"post /vote": "addVote",
		"get /delegate": "searchDelegate",
	});

	if (process.env.DEBUG) {
		var tmpKepairs = {};

		router.get('/forging/disableAll', function (req, res) {
			if (Object.keys(tmpKepairs).length !== 0) {
				return res.json({success: false});
			}

			tmpKepairs = privated.keypairs;
			privated.keypairs = {};
			return res.json({success: true});
		});

		router.get('/forging/enableAll', function (req, res) {
			if (Object.keys(tmpKepairs).length === 0) {
				return res.json({success: false});
			}

			privated.keypairs = tmpKepairs;
			tmpKepairs = {};
			return res.json({success: true});
		});
	}

	router.post('/forging/enable', function (req, res) {
		var body = req.body;
		library.scheme.validate(body, {
			type: "object",
			properties: {
				secret: {
					type: "string",
					minLength: 1,
					maxLength: 100
				},
				publicKey: {
					type: "string",
					format: "publicKey"
				}
			},
			required: ["secret"]
		}, function (err) {
			if (err) {
				return res.json({success: false, error: err[0].message});
			}

			var ip = req.connection.remoteAddress;

			if (library.config.forging.access.whiteList.length > 0 && library.config.forging.access.whiteList.indexOf(ip) < 0) {
				return res.json({success: false, error: "Access denied"});
			}

			var keypair = ed.MakeKeypair(crypto.createHash('sha256').update(body.secret, 'utf8').digest());

			if (body.publicKey) {
				if (keypair.publicKey.toString('hex') != body.publicKey) {
					return res.json({success: false, error: "Invalid passphrase"});
				}
			}

			if (privated.keypairs[keypair.publicKey.toString('hex')]) {
				return res.json({success: false, error: "Forging is already enabled"});
			}

			modules.accounts.getAccount({publicKey: keypair.publicKey.toString('hex')}, function (err, account) {
				if (err) {
					return res.json({success: false, error: err.toString()});
				}
				if (account && account.isDelegate) {
					privated.keypairs[keypair.publicKey.toString('hex')] = keypair;
					return res.json({success: true, address: account.address});
					library.logger.info("Forging enabled on account: " + account.address);
				} else {
					return res.json({success: false, error: "Delegate not found"});
				}
			});
		});
	});

	router.post('/forging/disable', function (req, res) {
		var body = req.body;
		library.scheme.validate(body, {
			type: "object",
			properties: {
				secret: {
					type: "string",
					minLength: 1,
					maxLength: 100
				},
				publicKey: {
					type: "string",
					format: "publicKey"
				}
			},
			required: ["secret"]
		}, function (err) {
			if (err) {
				return res.json({success: false, error: err[0].message});
			}

			var ip = req.connection.remoteAddress;

			if (library.config.forging.access.whiteList.length > 0 && library.config.forging.access.whiteList.indexOf(ip) < 0) {
				return res.json({success: false, error: "Access denied"});
			}

			var keypair = ed.MakeKeypair(crypto.createHash('sha256').update(body.secret, 'utf8').digest());

			if (body.publicKey) {
				if (keypair.publicKey.toString('hex') != body.publicKey) {
					return res.json({success: false, error: "Invalid passphrase"});
				}
			}

			if (!privated.keypairs[keypair.publicKey.toString('hex')]) {
				return res.json({success: false, error: "Delegate not found"});
			}

			modules.accounts.getAccount({publicKey: keypair.publicKey.toString('hex')}, function (err, account) {
				if (err) {
					return res.json({success: false, error: err.toString()});
				}
				if (account && account.isDelegate) {
					delete privated.keypairs[keypair.publicKey.toString('hex')];
					return res.json({success: true, address: account.address});
					library.logger.info("Forging disabled on account: " + account.address); //fixme
				} else {
					return res.json({success: false, error: "Delegate not found"});
				}
			});
		});
	});

	router.get('/forging/status', function (req, res) {
		var query = req.query;
		library.scheme.validate(query, {
			type: "object",
			properties: {
				publicKey: {
					type: "string",
					format: "publicKey"
				}
			},
			required: ["publicKey"]
		}, function (err) {
			if (err) {
				return res.json({success: false, error: err[0].message});
			}

			return res.json({success: true, enabled: !!privated.keypairs[query.publicKey]});
		});
	});

	/*router.map(privated, {
	 "post /forging/enable": "enableForging",
	 "post /forging/disable": "disableForging",
	 "get /forging/status": "statusForging"
	 });*/

	library.network.app.use('/api/delegates', router);
	library.network.app.use(function (err, req, res, next) {
		if (!err) return next();
		library.logger.error(req.url, err.toString());
		res.status(500).send({success: false, error: err.toString()});
	});
};

privated.getKeysSortByVote = function (cb) {
	modules.accounts.getAccounts({
		isDelegate: 1,
		sort: {"vote": -1, "publicKey": 1},
		limit: constants.delegates
	}, ["publicKey"], function (err, rows) {
		if (err) {
			cb(err);
		}
		cb(null, rows.map(function (el) {
			return el.publicKey;
		}));
	});
};

privated.getBlockSlotData = function (slot, height, cb) {
	self.generateDelegateList(height, function (err, activeDelegates) {
		if (err) {
			return cb(err);
		}
		var currentSlot = slot;
		var lastSlot = slots.getLastSlot(currentSlot);

		for (; currentSlot < lastSlot; currentSlot += 1) {
			var delegate_pos = currentSlot % constants.delegates;

			var delegate_id = activeDelegates[delegate_pos];

			if (delegate_id && privated.keypairs[delegate_id]) {
				return cb(null, {time: slots.getSlotTime(currentSlot), keypair: privated.keypairs[delegate_id]});
			}
		}
		cb(null, null);
	});
};

//
privated.loop = function (cb) {
	if (!Object.keys(privated.keypairs).length) {
		library.logger.debug('Loop', 'exit: no delegates');
		return setImmediate(cb);
	}

	if (!privated.loaded || modules.loader.syncing() || !modules.round.loaded()) {
		// library.logger.log('Loop', 'exit: syncing');
		return setImmediate(cb);
	}

	var currentSlot = slots.getSlotNumber();
	var lastBlock = modules.blocks.getLastBlock();

	if (currentSlot == slots.getSlotNumber(lastBlock.timestamp)) {
		// library.logger.log('Loop', 'exit: lastBlock is in the same slot');
		return setImmediate(cb);
	}

	privated.getBlockSlotData(currentSlot, lastBlock.height + 1, function (err, currentBlockData) {
		if (err || currentBlockData === null) {
			library.logger.log('Loop', 'skiping slot');
			return setImmediate(cb);
		}

		library.sequence.add(function (cb) {
			if (slots.getSlotNumber(currentBlockData.time) == slots.getSlotNumber()) {
				modules.blocks.generateBlock(currentBlockData.keypair, currentBlockData.time, function (err) {
					library.logger.log('Round ' + modules.round.calc(modules.blocks.getLastBlock().height) + ' new block id: ' + modules.blocks.getLastBlock().id + ' height: ' + modules.blocks.getLastBlock().height + ' slot: ' + slots.getSlotNumber(currentBlockData.time) + ' reward: ' + modules.blocks.getLastBlock().reward);
					cb(err);
				});
			} else {
				// library.logger.log('Loop', 'exit: ' + _activeDelegates[slots.getSlotNumber() % constants.delegates] + ' delegate slot');
				setImmediate(cb);
			}
		}, function (err) {
			if (err) {
				library.logger.error("Failed to get block slot data", err);
			}
			setImmediate(cb);
		});
	});
};

privated.loadMyDelegates = function (cb) {
	var secrets = null;
	if (library.config.forging.secret) {
		secrets = util.isArray(library.config.forging.secret) ? library.config.forging.secret : [library.config.forging.secret];
	}

	async.eachSeries(secrets, function (secret, cb) {
		var keypair = ed.MakeKeypair(crypto.createHash('sha256').update(secret, 'utf8').digest());

		modules.accounts.getAccount({
			publicKey: keypair.publicKey.toString('hex')
		}, function (err, account) {
			if (err) {
				return cb(err);
			}

			if (!account) {
				return cb("Account " + keypair.publicKey.toString('hex') + " not found");
			}

			if (account.isDelegate) {
				privated.keypairs[keypair.publicKey.toString('hex')] = keypair;
				library.logger.info("Forging enabled on account: " + account.address);
			} else {
				library.logger.info("Delegate with this public key not found: " + keypair.publicKey.toString('hex'));
			}
			cb();
		});
	}, cb);
};

// Public methods	//查询排名前101节点
Delegates.prototype.generateDelegateList = function (height, cb) {
	privated.getKeysSortByVote(function (err, truncDelegateList) {
		if (err) {
			return cb(err);
		}
		var seedSource = modules.round.calc(height).toString();

		var currentSeed = crypto.createHash('sha256').update(seedSource, 'utf8').digest();
		for (var i = 0, delCount = truncDelegateList.length; i < delCount; i++) {
			for (var x = 0; x < 4 && i < delCount; i++, x++) {
				var newIndex = currentSeed[x] % delCount;
				var b = truncDelegateList[newIndex];
				truncDelegateList[newIndex] = truncDelegateList[i];
				truncDelegateList[i] = b;
			}
			currentSeed = crypto.createHash('sha256').update(currentSeed).digest();
		}

		cb(null, truncDelegateList);
	});

};

Delegates.prototype.checkDelegates = function (publicKey, votes, cb) {
	if (util.isArray(votes)) {
		modules.accounts.getAccount({publicKey: publicKey}, function (err, account) {
			if (err) {
				return cb(err);
			}
			if (!account) {
				return cb("Account not found");
			}

			async.eachSeries(votes, function (action, cb) {
				var math = action[0];

				if (math !== '+' && math !== '-') {
					return cb("Invalid math operator");
				}

				var publicKey = action.slice(1);

				try {
					new Buffer(publicKey, "hex");
				} catch (e) {
					return cb("Invalid public key");
				}

				if (math == "+" && (account.delegates !== null && account.delegates.indexOf(publicKey) != -1)) {
					return cb("Failed to add vote, account has already voted for this delegate");
				}
				if (math == "-" && (account.delegates === null || account.delegates.indexOf(publicKey) === -1)) {
					return cb("Failed to remove vote, account has not voted for this delegate");
				}

				modules.accounts.getAccount({publicKey: publicKey, isDelegate: 1}, function (err, account) {
					if (err) {
						return cb(err);
					}

					if (!account) {
						return cb("Delegate not found");
					}

					cb();
				});
			}, cb);
		});
	} else {
		setImmediate(cb, "Please provide an array of votes");
	}
};

Delegates.prototype.checkUnconfirmedDelegates = function (publicKey, votes, cb) {
	if (util.isArray(votes)) {
		modules.accounts.getAccount({publicKey: publicKey}, function (err, account) {
			if (err) {
				return cb(err);
			}
			if (!account) {
				return cb("Account not found");
			}

			async.eachSeries(votes, function (action, cb) {
				var math = action[0];

				if (math !== '+' && math !== '-') {
					return cb("Invalid math operator");
				}

				var publicKey = action.slice(1);


				try {
					new Buffer(publicKey, "hex");
				} catch (e) {
					return cb("Invalid public key");
				}

				if (math == "+" && (account.u_delegates !== null && account.u_delegates.indexOf(publicKey) != -1)) {
					return cb("Failed to add vote, account has already voted for this delegate");
				}
				if (math == "-" && (account.u_delegates === null || account.u_delegates.indexOf(publicKey) === -1)) {
					return cb("Failed to remove vote, account has not voted for this delegate");
				}

				modules.accounts.getAccount({publicKey: publicKey, isDelegate: 1}, function (err, account) {
					if (err) {
						return cb(err);
					}

					if (!account) {
						return cb("Delegate not found");
					}

					cb();
				});
			}, cb);
		});
	} else {
		return setImmediate(cb, "Please provide an array of votes");
	}
};

Delegates.prototype.fork = function (block, cause) {
	library.logger.info('Fork', {
		delegate: block.generatorPublicKey,
		block: {id: block.id, timestamp: block.timestamp, height: block.height, previousBlock: block.previousBlock},
		cause: cause
	});
	library.dbLite.query("INSERT INTO forks_stat (delegatePublicKey, blockTimestamp, blockId, blockHeight, previousBlock, cause) " +
		"VALUES ($delegatePublicKey, $blockTimestamp, $blockId, $blockHeight, $previousBlock, $cause);", {
		delegatePublicKey: block.generatorPublicKey,
		blockTimestamp: block.timestamp,
		blockId: block.id,
		blockHeight: block.height,
		previousBlock: block.previousBlock,
		cause: cause
	});
};

Delegates.prototype.validateBlockSlot = function (block, cb) {
	self.generateDelegateList(block.height, function (err, activeDelegates) {
		if (err) {
			return cb(err);
		}
		var currentSlot = slots.getSlotNumber(block.timestamp);
		var delegate_id = activeDelegates[currentSlot % constants.delegates];

		if (delegate_id && block.generatorPublicKey == delegate_id) {
			return cb();
		} else {
			library.logger.error("Expected generator: " + delegate_id + " Received generator: " + block.generatorPublicKey);
			return cb("Failed to verify slot: " + currentSlot);
		}
	});
};

Delegates.prototype.sandboxApi = function (call, args, cb) {
	sandboxHelper.callMethod(shared, call, args, cb);
};

// Events
Delegates.prototype.onBind = function (scope) {
	modules = scope;
};

Delegates.prototype.onBlockchainReady = function () {
	privated.loaded = true;

	privated.loadMyDelegates(function nextLoop(err) {
		if (err) {
			library.logger.error("Failed to load delegates", err);
		}

		privated.loop(function () {
			setTimeout(nextLoop, 1000);
		});

	});
};

Delegates.prototype.cleanup = function (cb) {
	privated.loaded = false;
	cb();
};

/**
 * @apiGroup Delegate
 * @apiName addDelegate
 *
 * @api {PUT} /api/delegates
 * @apiVersion 0.1.3
 *
 * @apiParam {String} secret Secret key of account.
 * @apiSuccess {Object} transaction A transaction object.
 *
 * @apiParamExample {json} Request(Example)
 *
 * {
 *     "secret" : "Secret key of account",
 *     "secondSecret": "Second secret of account",
 *     "username" : "Username of delegate. String from 1 to 20 characters."
 * }
 *
 * @apiSuccessExample {json} Response(Example)
 * {
 *     "success": true,
 *     "transaction": "transaction object"
 * }
 */
shared.addDelegate = function (req, cb) {
	var body = req.body;
	library.scheme.validate(body, {
		type: "object",
		properties: {
			SECRET: {
				type: "string",
				minLength: 1,
				maxLength: 100
			},
			publicKey: {
				type: "string",
				format: "publicKey"
			},
			secondSecret: {
				type: "string",
				minLength: 1,
				maxLength: 100
			},
			USERNAME: {
				type: "string"
			}
		},
		required: ["SECRET"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		var hash = crypto.createHash('sha256').update(body.SECRET, 'utf8').digest();
		var keypair = ed.MakeKeypair(hash);

		if (body.publicKey) {
			if (keypair.publicKey.toString('hex') != body.publicKey) {
				return cb("Invalid passphrase");
			}
		}

		library.balancesSequence.add(function (cb) {
			if (body.multisigAccountPublicKey && body.multisigAccountPublicKey != keypair.publicKey.toString('hex')) {
				modules.accounts.getAccount({publicKey: body.multisigAccountPublicKey}, function (err, account) {
					if (err) {
						return cb(err.toString());
					}

					if (!account || !account.publicKey) {
						return cb("Multisignature account not found");
					}

					if (!account.multisignatures || !account.multisignatures) {
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

						if (requester.secondSignature && !body.secondSecret) {
							return cb("Invalid second passphrase");
						}

						if (requester.publicKey == account.publicKey) {
							return cb("Incorrect requester");
						}

						var secondKeypair = null;

						if (requester.secondSignature) {
							var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
							secondKeypair = ed.MakeKeypair(secondHash);
						}

						try {
							var transaction = library.logic.transaction.create({
								type: TransactionTypes.DELEGATE,
								username: body.USERNAME,
								sender: account,
								keypair: keypair,
								secondKeypair: secondKeypair,
								requester: keypair
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

					if (account.secondSignature && !body.secondSecret) {
						return cb("Invalid second passphrase");
					}

					var secondKeypair = null;

					if (account.secondSignature) {
						var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
						secondKeypair = ed.MakeKeypair(secondHash);
					}

					try {
						var transaction = library.logic.transaction.create({
							type: TransactionTypes.DELEGATE,
							username: body.USERNAME,
							sender: account,
							keypair: keypair,
							secondKeypair: secondKeypair
						});
					} catch (e) {
						return cb(e.toString());
					}
					modules.transactions.receiveTransactions([transaction], cb);
				});
			}
		}, function (err, transaction) {
			if (err) {
				return cb(err.toString());
			}

			cb(null, {transaction: transaction[0]});
		});
	});
};


shared.addVote = function (req, cb) {
	var body = req.body;
	library.scheme.validate(body, {
		type: "object",
		properties: {
			SECRET: {
				type: 'string',
				minLength: 1
			},
			publicKey: {
				type: 'string',
				format: 'publicKey'
			},
			secondSecret: {
				type: 'string',
				minLength: 1
			}
		},
		required: ["SECRET","DELEGATES"]
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		var hash = crypto.createHash('sha256').update(body.SECRET, 'utf8').digest();
		var keypair = ed.MakeKeypair(hash);

		if (body.publicKey) {
			if (keypair.publicKey.toString('hex') != body.publicKey) {
				return cb("Invalid passphrase");
			}
		}

		library.balancesSequence.add(function (cb) {
			if (body.multisigAccountPublicKey && body.multisigAccountPublicKey != keypair.publicKey.toString('hex')) {
				modules.accounts.getAccount({publicKey: body.multisigAccountPublicKey}, function (err, account) {
					if (err) {
						return cb(err.toString());
					}

					if (!account || !account.publicKey) {
						return cb("Multisignature account not found");
					}

					if (!account.multisignatures || !account.multisignatures) {
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

						if (requester.secondSignature && !body.secondSecret) {
							return cb("Invalid second passphrase");
						}

						if (requester.publicKey == account.publicKey) {
							return cb("Invalid requester");
						}

						var secondKeypair = null;

						if (requester.secondSignature) {
							var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
							secondKeypair = ed.MakeKeypair(secondHash);
						}

						try {
							var transaction = library.logic.transaction.create({
								type: TransactionTypes.VOTE,
								votes: body.DELEGATES,
								sender: account,
								keypair: keypair,
								secondKeypair: secondKeypair,
								requester: keypair
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

					if (account.secondSignature && !body.secondSecret) {
						return cb("Invalid second passphrase");
					}

					var secondKeypair = null;

					if (account.secondSignature) {
						var secondHash = crypto.createHash('sha256').update(body.secondSecret, 'utf8').digest();
						secondKeypair = ed.MakeKeypair(secondHash);
					}

					try {
						var transaction = library.logic.transaction.create({
							type: TransactionTypes.VOTE,
							votes: body.DELEGATES,
							sender: account,
							keypair: keypair,
							secondKeypair: secondKeypair
						});
					} catch (e) {
						return cb(e.toString());
					}
					modules.transactions.receiveTransactions([transaction], cb);
				});
			}
		}, function (err, transaction) {
			if (err) {
				return cb(err.toString());
			}

			cb(null, {transaction: transaction[0]});
		});
	});
};

shared.searchDelegate = function (req, cb) {
	var body = req.body;
	library.scheme.validate(body, {
		type: "object",
		properties: {
			address: {
				type: "string",
				minLength: 1
			}
		}
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}
		var address=body.ADDRESS||null;
		if(address==null) {
			library.dbLite.query("select address from mem_accounts where isDelegate=1", ["ADDRESS"], function (err, rows) {
				if (rows.length > 0) {
					return cb(null, {data: rows});
				} else {
					cb("没有委托人")
				}
			});
		}else{
			library.dbLite.query("select address from mem_accounts where isDelegate=1 and address=$address",{address:address},["ADDRESS"], function (err, rows) {
				if (rows.length > 0) {
					return cb(null, {data: rows});
				} else {
					cb("不是委托人")
				}
			});
		}
	});
};

// Export
module.exports = Delegates;
