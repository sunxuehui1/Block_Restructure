var crypto = require('crypto');
var	ed = require('ed25519');
var	ip = require('ip');
var	ByteBuffer = require("bytebuffer");
var	constants = require("../helpers/constants.js");
var	genesisblock = null;
var	milestones = require("../helpers/milestones.js");
var	constants = require('../helpers/constants.js');
var	Router = require('../helpers/router.js');
var	slots = require('../helpers/slots.js');
var	util = require('util');
var	async = require('async');
var	TransactionTypes = require('../helpers/transaction-types.js');
var	sandboxHelper = require('../helpers/sandbox.js');

require('array.prototype.findindex'); // Old node fix

// private fields
var modules, library, self, privated = {}, shared = {};

privated.lastBlock = {};
privated.milestones = new milestones();
// @formatter:off
privated.blocksDataFields = {
	'b_id': String,
	'b_version': String,
	'b_timestamp': Number,
	'b_height': Number,
	'b_previousBlock': String,
	'b_numberOfTransactions': String,
	'b_totalAmount': String,
	'b_totalFee': String,
	'b_reward': String,
	'b_payloadLength': String,
	'b_payloadHash': String,
	'b_generatorPublicKey': String,
	'b_blockSignature': String,
	't_id': String,
	't_type': Number,
	't_timestamp': String,
	't_senderPublicKey': String,
	't_senderId': String,
	't_recipientId': String,
	't_senderUsername': String,
	't_recipientUsername': String,
	't_amount': String,
	't_fee': String,
	't_signature': String,
	't_signSignature': String,
	's_publicKey': String,
	'd_username': String,
	'v_votes': String,
	'c_address': String,
	'u_alias': String,
	'm_min': Number,
	'm_lifetime': Number,
	'm_keysgroup': String,
	'dapp_name': String,
	'dapp_description': String,
	'dapp_tags': String,
	'dapp_type': Number,
	'dapp_siaAscii': String,
	'dapp_siaIcon': String,
	'dapp_git': String,
	'dapp_category': Number,
	'dapp_icon': String,
	'in_dappId': String,
	'ot_dappId': String,
	'ot_outTransactionId': String,
	't_requesterPublicKey': String,
	't_signatures': String
};
// @formatter:on
privated.loaded = false;
privated.isActive = false;

// Constructor
function Blocks(cb, scope) {
	library = scope;
	genesisblock = library.genesisblock;
	self = this;
	self.__private = privated;
	privated.attachApi();

	privated.saveGenesisBlock(function (err) {
		setImmediate(cb, err, self);
	});
}

// private methods
privated.attachApi = function () {
	var router = new Router();

	router.use(function (req, res, next) {
		if (modules) return next();
		res.status(500).send({success: false, error: "Blockchain is loading"});
	});

	router.map(shared, {
		"get /": "getBlocks"
	});

	router.use(function (req, res, next) {
		res.status(500).send({success: false, error: "API endpoint not found"});
	});

	library.network.app.use('/api/blocks', router);
	library.network.app.use(function (err, req, res, next) {
		if (!err) return next();
		library.logger.error(req.url, err.toString());
		res.status(500).send({success: false, error: err.toString()});
	});
};

privated.saveGenesisBlock = function (cb) {
	library.dbLite.query("SELECT id FROM blocks WHERE id=$id", {id: genesisblock.block.id}, ['id'], function (err, rows) {
		if (err) {
			return cb(err);
		}
		var blockId = rows.length && rows[0].id;

		if (!blockId) {
			privated.saveBlock(genesisblock.block, function (err) {
				if (err) {
					library.logger.error('saveBlock', err);
				}

				return cb(err);
			});
		} else {
			return cb();
		}
	});
};

privated.deleteBlock = function (blockId, cb) {
	library.dbLite.query("DELETE FROM blocks WHERE id = $id", {id: blockId}, function (err, res) {
		cb(err, res);
	});
};

privated.list = function (filter, cb) {
	var params = {}, fields = [];
	if (filter.ID) {
		fields.push('id = ID');
		params.ID = filter.ID;
	}

	if (filter.PREVIOUS_BLOCK) {
		fields.push('previousBlock = $PREVIOUS_BLOCK');
		params.PREVIOUS_BLOCK = filter.PREVIOUS_BLOCK;
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

		library.dbLite.query("SELECT id,version,timestamp,height,previousBlock,numberOfTransactions,totalAmount,totalFee,reward FROM blocks" + 
			(fields.length ? (' where ' + fields.join(' and ')) : '') + " " +
			(params.start ? ' offset $start' : '') +
			(params.limit ? ' limit $limit ' : ''),
			params,['ID','VERSION','TIMESTAMP','HEIGHT','PREVIOUS_ID','NUMBER_OF_TRANSACTIONS','TOTALAMOUNT','TOTALFEE','REWARD'], function (err, rows) {
				var data = {};
				data.blocks = rows;
				for(var i = 0;i < data.blocks.length;i++) {
					data.blocks[i].ROOT_ID = "039abdb00e4b16e1a331e242c616d83b35e8bcf0";
					data.blocks[i].SIZE = (10 + Number((data.blocks[i].NUMBER_OF_TRANSACTIONS/10).toFixed(1))) + "KB";
				}
				library.dbLite.query("select id from blocks" + 
				(fields.length ? (' where ' + fields.join(' and ')) : ''),
				params, ['id'], function (err, rows) {
					data.count = rows.length;
					cb(null, data);
				});
		});
    }

privated.getById = function (id, cb) {
	library.dbLite.query("select b.id, b.version, b.timestamp, b.height, b.previousBlock, b.numberOfTransactions, b.totalAmount, b.totalFee, b.reward, b.payloadLength,  lower(hex(b.payloadHash)), lower(hex(b.generatorPublicKey)), lower(hex(b.blockSignature)), (select max(height) + 1 from blocks) - b.height " +
		"from blocks b " +
		"where b.id = $id", {id: id}, ['b_id', 'b_version', 'b_timestamp', 'b_height', 'b_previousBlock', 'b_numberOfTransactions', 'b_totalAmount', 'b_totalFee', 'b_reward', 'b_payloadLength', 'b_payloadHash', 'b_generatorPublicKey', 'b_blockSignature', 'b_confirmations'], function (err, rows) {
		if (err || !rows.length) {
			return cb(err || "Block not found");
		}

		var block = library.logic.block.dbRead(rows[0]);
		cb(null, block);
	});
};

privated.saveBlock = function (block, cb) {
	library.dbLite.query('BEGIN TRANSACTION;');

	library.logic.block.dbSave(block, function (err) {
		if (err) {
			library.dbLite.query('ROLLBACK;', function (rollbackErr) {
				cb(rollbackErr || err);
			});
			return;
		}

		async.eachSeries(block.transactions, function (transaction, cb) {
			transaction.blockId = block.id;
			library.logic.transaction.dbSave(transaction, cb);
		}, function (err) {
			if (err) {
				library.dbLite.query('ROLLBACK;', function (rollbackErr) {
					cb(rollbackErr || err);
				});
				return;
			}

			library.dbLite.query('COMMIT;', cb);
		});
	});
};

privated.popLastBlock = function (oldLastBlock, cb) {
	library.balancesSequence.add(function (cb) {
		self.loadBlocksPart({id: oldLastBlock.previousBlock}, function (err, previousBlock) {
			if (err || !previousBlock.length) {
				return cb(err || 'previousBlock is null');
			}
			previousBlock = previousBlock[0];

			async.eachSeries(oldLastBlock.transactions.reverse(), function (transaction, cb) {
				async.series([
					function (cb) {
						modules.accounts.getAccount({publicKey: transaction.senderPublicKey}, function (err, sender) {
							if (err) {
								return cb(err);
							}
							modules.transactions.undo(transaction, oldLastBlock, sender, cb);
						});
					}, function (cb) {
						modules.transactions.undoUnconfirmed(transaction, cb);
					}, function (cb) {
						modules.transactions.pushHiddenTransaction(transaction);
						setImmediate(cb);
					}
				], cb);
			}, function (err) {
				modules.round.backwardTick(oldLastBlock, previousBlock, function () {
					privated.deleteBlock(oldLastBlock.id, function (err) {
						if (err) {
							return cb(err);
						}

						cb(null, previousBlock);
					});
				});
			});
		});
	}, cb);
};

privated.getIdSequence = function (height, cb) {
	library.dbLite.query("SELECT s.height, group_concat(s.id) from ( " +
		'SELECT id, max(height) as height ' +
		'FROM blocks ' +
		'group by (cast(height / $delegates as integer) + (case when height % $delegates > 0 then 1 else 0 end)) having height <= $height ' +
		'union ' +
		'select id, 1 as height ' +
		'from blocks where height = 1 ' +
		'order by height desc ' +
		'limit $limit ' +
		') s', {
		'height': height,
		'limit': 1000,
		'delegates': constants.delegates
	}, ['firstHeight', 'ids'], function (err, rows) {
		if (err || !rows.length) {
			cb(err ? err.toString() : "Can't get sequence before: " + height);
			return;
		}

		cb(null, rows[0]);
	})
};

privated.readDbRows = function (rows) {
	var blocks = {};
	var order = [];
	for (var i = 0, length = rows.length; i < length; i++) {
		var __block = library.logic.block.dbRead(rows[i]);
		if (__block) {
			if (!blocks[__block.id]) {
				if (__block.id == genesisblock.block.id) {
					__block.generationSignature = (new Array(65)).join('0');
				}

				order.push(__block.id);
				blocks[__block.id] = __block;
			}

			var __transaction = library.logic.transaction.dbRead(rows[i]);
			blocks[__block.id].transactions = blocks[__block.id].transactions || {};
			if (__transaction) {
				if (!blocks[__block.id].transactions[__transaction.id]) {
					blocks[__block.id].transactions[__transaction.id] = __transaction;
				}
			}
		}
	}

	blocks = order.map(function (v) {
		blocks[v].transactions = Object.keys(blocks[v].transactions).map(function (t) {
			return blocks[v].transactions[t];
		});
		return blocks[v];
	});

	return blocks;
};

privated.applyTransaction = function (block, transaction, sender, cb) {
	modules.transactions.applyUnconfirmed(transaction, sender, function (err) {
		if (err) {
			return setImmediate(cb, {
				message: err,
				transaction: transaction,
				block: block
			});
		}

		modules.transactions.apply(transaction, block, sender, function (err) {
			if (err) {
				return setImmediate(cb, {
					message: "Can't apply transaction: " + transaction.id,
					transaction: transaction,
					block: block
				});
			}
			setImmediate(cb);
		});
	});
};

// Public methods
Blocks.prototype.getCommonBlock = function (peer, height, cb) {
	var commonBlock = null;
	var lastBlockHeight = height;
	var count = 0;

	async.whilst(
		function () {
			return !commonBlock && count < 30 && lastBlockHeight > 1;
		},
		function (next) {
			count++;
			privated.getIdSequence(lastBlockHeight, function (err, data) {
				if (err) {
					return next(err);
				}
				var max = lastBlockHeight;
				lastBlockHeight = data.firstHeight;
				modules.transport.getFromPeer(peer, {
					api: "/blocks/common?ids=" + data.ids + '&max=' + max + '&min=' + lastBlockHeight,
					method: "GET"
				}, function (err, data) {
					if (err || data.body.error) {
						return next(err || data.body.error.toString());
					}

					if (!data.body.common) {
						return next();
					}

					library.dbLite.query("select count(*) from blocks where id = $id " + (data.body.common.previousBlock ? "and previousBlock = $previousBlock" : "") + " and height = $height", {
						"id": data.body.common.id,
						"previousBlock": data.body.common.previousBlock,
						"height": data.body.common.height
					}, {
						"cnt": Number
					}, function (err, rows) {
						if (err || !rows.length) {
							return next(err || "Can't compare blocks");
						}

						if (rows[0].cnt) {
							commonBlock = data.body.common;
						}
						next();
					});
				});
			});
		},
		function (err) {
			setImmediate(cb, err, commonBlock);
		}
	);
};

Blocks.prototype.count = function (cb) {
	library.dbLite.query("select count(rowid) from blocks", {"count": Number}, function (err, rows) {
		if (err) {
			return cb(err);
		}

		var res = rows.length ? rows[0].count : 0;

		cb(null, res);
	});
};

Blocks.prototype.loadBlocksData = function (filter, options, cb) {
	if (arguments.length < 3) {
		cb = options;
		options = {};
	}

	options = options || {};

	if (filter.lastId && filter.id) {
		return cb("Invalid filter");
	}

	var params = {limit: filter.limit || 1};
	filter.lastId && (params.lastId = filter.lastId);
	filter.id && !filter.lastId && (params.id = filter.id);

	var fields = privated.blocksDataFields;
	var method;

	if (options.plain) {
		method = 'plain';
		fields = false;
	} else {
		method = 'query';
	}

	library.dbSequence.add(function (cb) {
		// "FROM (select * from blocks " + (filter.id ? " where id = $id " : "") + (filter.lastId ? " where height > (SELECT height FROM blocks where id = $lastId) " : "") + " limit $limit) as b " +

		library.dbLite.query("SELECT height FROM blocks where id = $lastId", {
			lastId: filter.lastId || null
		}, {'height': Number}, function (err, rows) {
			if (err) {
				return cb(err);
			}

			// (filter.lastId? " where height > (SELECT height FROM blocks where id = $lastId)" : "") +

			var height = rows.length ? rows[0].height : 0;
			var realLimit = height + (parseInt(filter.limit) || 1);
			params.limit = realLimit;
			params.height = height;

			var limitPart = "";

			if (!filter.id && !filter.lastId) {
				limitPart = "where b.height < $limit ";
			}

			library.dbLite[method]("SELECT " +
				"b.id, b.version, b.timestamp, b.height, b.previousBlock, b.numberOfTransactions, b.totalAmount, b.totalFee, b.reward, b.payloadLength, lower(hex(b.payloadHash)), lower(hex(b.generatorPublicKey)), lower(hex(b.blockSignature)), " +
				"t.id, t.type, t.timestamp, lower(hex(t.senderPublicKey)), t.senderId, t.recipientId, t.senderUsername, t.recipientUsername, t.amount, t.fee, lower(hex(t.signature)), lower(hex(t.signSignature)), " +
				"lower(hex(s.publicKey)), " +
				"d.username, " +
				"v.votes, " +
				"c.address, " +
				"u.username, " +
				"m.min, m.lifetime, m.keysgroup, " +
				"dapp.name, dapp.description, dapp.tags, dapp.type, dapp.siaAscii, dapp.siaIcon, dapp.git, dapp.category, dapp.icon, " +
				"it.dappId, " +
				"ot.dappId, ot.outTransactionId, " +
				"lower(hex(t.requesterPublicKey)), t.signatures " +
				"FROM blocks b " +
				"left outer join trs as t on t.blockId=b.id " +
				"left outer join delegates as d on d.transactionId=t.id " +
				"left outer join votes as v on v.transactionId=t.id " +
				"left outer join signatures as s on s.transactionId=t.id " +
				"left outer join contacts as c on c.transactionId=t.id " +
				"left outer join usernames as u on u.transactionId=t.id " +
				"left outer join multisignatures as m on m.transactionId=t.id " +
				"left outer join dapps as dapp on dapp.transactionId=t.id " +
				"left outer join intransfer it on it.transactionId=t.id " +
				"left outer join outtransfer ot on ot.transactionId=t.id " +
				(filter.id || filter.lastId ? "where " : "") + " " +
				(filter.id ? " b.id = $id " : "") + (filter.id && filter.lastId ? " and " : "") + (filter.lastId ? " b.height > $height and b.height < $limit " : "") +
				limitPart +
				"ORDER BY b.height, t.rowid" +
				"", params, fields, cb);
		});

	}, cb);
};

Blocks.prototype.loadBlocksPart = function (filter, cb) {
	self.loadBlocksData(filter, function (err, rows) {
		// Notes:
		// If while loading we encounter an error, for example, an invalid signature on
		// a block & transaction, then we need to stop loading and remove all blocks
		// after the last good block. We also need to process all transactions within
		// the block.

		var blocks = [];

		if (!err) {
			blocks = privated.readDbRows(rows);
		}

		cb(err, blocks);
	});
};

Blocks.prototype.loadBlocksOffset = function (limit, offset, verify, cb) {
	var newLimit = limit + (offset || 0);
	var params = {limit: newLimit, offset: offset || 0};

	library.dbSequence.add(function (cb) {
		library.dbLite.query("SELECT " +
			"b.id, b.version, b.timestamp, b.height, b.previousBlock, b.numberOfTransactions, b.totalAmount, b.totalFee, b.reward, b.payloadLength, lower(hex(b.payloadHash)), lower(hex(b.generatorPublicKey)), lower(hex(b.blockSignature)), " +
			"t.id, t.type, t.timestamp, lower(hex(t.senderPublicKey)), t.senderId, t.recipientId, t.senderUsername, t.recipientUsername, t.amount, t.fee, lower(hex(t.signature)), lower(hex(t.signSignature)), " +
			"lower(hex(s.publicKey)), " +
			"d.username, " +
			"v.votes, " +
			"c.address, " +
			"u.username, " +
			"m.min, m.lifetime, m.keysgroup, " +
			"dapp.name, dapp.description, dapp.tags, dapp.type, dapp.siaAscii, dapp.siaIcon, dapp.git, dapp.category, dapp.icon, " +
			"it.dappId, " +
			"ot.dappId, ot.outTransactionId, " +
			"lower(hex(t.requesterPublicKey)), t.signatures " +
			"FROM blocks b " +
			"left outer join trs as t on t.blockId=b.id " +
			"left outer join delegates as d on d.transactionId=t.id " +
			"left outer join votes as v on v.transactionId=t.id " +
			"left outer join signatures as s on s.transactionId=t.id " +
			"left outer join contacts as c on c.transactionId=t.id " +
			"left outer join usernames as u on u.transactionId=t.id " +
			"left outer join multisignatures as m on m.transactionId=t.id " +
			"left outer join dapps as dapp on dapp.transactionId=t.id " +
			"left outer join intransfer it on it.transactionId=t.id " +
			"left outer join outtransfer ot on ot.transactionId=t.id " +
			"where b.height >= $offset and b.height < $limit " +
			"ORDER BY b.height, t.rowid" +
			"", params, privated.blocksDataFields, function (err, rows) {
			// Notes:
			// If while loading we encounter an error, for example, an invalid signature on a block & transaction, then we need to stop loading and remove all blocks after the last good block. We also need to process all transactions within the block.
			if (err) {
				return cb(err);
			}

			var blocks = privated.readDbRows(rows);

			async.eachSeries(blocks, function (block, cb) {
				async.series([
					function (cb) {
						if (block.id != genesisblock.block.id) {
							if (verify) {
								if (block.previousBlock != privated.lastBlock.id) {
									return cb({
										message: "Can't verify previous block",
										block: block
									});
								}

								try {
									var valid = library.logic.block.verifySignature(block);
								} catch (e) {
									return setImmediate(cb, {
										message: e.toString(),
										block: block
									});
								}
								if (!valid) {
									// Need to break cycle and delete this block and blocks after this block
									return cb({
										message: "Can't verify signature",
										block: block
									});
								}

								modules.delegates.validateBlockSlot(block, function (err) {
									if (err) {
										return cb({
											message: "Can't verify slot",
											block: block
										});
									}
									cb();
								});
							} else {
								setImmediate(cb);
							}
						} else {
							setImmediate(cb);
						}
					}, function (cb) {
						block.transactions = block.transactions.sort(function (a, b) {
							if (block.id == genesisblock.block.id) {
								if (a.type == TransactionTypes.VOTE)
									return 1;
							}

							if (a.type == TransactionTypes.SIGNATURE) {
								return 1;
							}

							return 0;
						});

						async.eachSeries(block.transactions, function (transaction, cb) {
							if (verify) {
								modules.accounts.setAccountAndGet({publicKey: transaction.senderPublicKey}, function (err, sender) {
									if (err) {
										return cb({
											message: err,
											transaction: transaction,
											block: block
										});
									}
									if (verify && block.id != genesisblock.block.id) {
										library.logic.transaction.verify(transaction, sender, function (err) {
											if (err) {
												return setImmediate(cb, {
													message: err,
													transaction: transaction,
													block: block
												});
											}
											privated.applyTransaction(block, transaction, sender, cb);
										});
									} else {
										privated.applyTransaction(block, transaction, sender, cb);
									}
								});
							} else {
								setImmediate(cb);
							}
						}, function (err) {
							if (err) {
								library.logger.error(err);
								var lastValidTransaction = block.transactions.findIndex(function (trs) {
									return trs.id == err.transaction.id;
								});
								var transactions = block.transactions.slice(0, lastValidTransaction + 1);
								async.eachSeries(transactions.reverse(), function (transaction, cb) {
									async.series([
										function (cb) {
											modules.accounts.getAccount({publicKey: transaction.senderPublicKey}, function (err, sender) {
												if (err) {
													return cb(err);
												}
												modules.transactions.undo(transaction, block, sender, cb);
											});
										}, function (cb) {
											modules.transactions.undoUnconfirmed(transaction, cb);
										}
									], cb);
								}, cb);
							} else {
								privated.lastBlock = block;

								modules.round.tick(privated.lastBlock, cb);
							}
						});
					}
				], cb);
			}, function (err) {
				cb(err, privated.lastBlock);
			});
		});
	}, cb);
};

Blocks.prototype.loadLastBlock = function (cb) {
	library.dbSequence.add(function (cb) {
		library.dbLite.query("SELECT " +
			"b.id, b.version, b.timestamp, b.height, b.previousBlock, b.numberOfTransactions, b.totalAmount, b.totalFee, b.reward, b.payloadLength, lower(hex(b.payloadHash)), lower(hex(b.generatorPublicKey)), lower(hex(b.blockSignature)), " +
			"t.id, t.type, t.timestamp, lower(hex(t.senderPublicKey)), t.senderId, t.recipientId, t.senderUsername, t.recipientUsername, t.amount, t.fee, lower(hex(t.signature)), lower(hex(t.signSignature)), " +
			"lower(hex(s.publicKey)), " +
			"d.username, " +
			"v.votes, " +
			"c.address, " +
			"u.username, " +
			"m.min, m.lifetime, m.keysgroup, " +
			"dapp.name, dapp.description, dapp.tags, dapp.type, dapp.siaAscii, dapp.siaIcon, dapp.git, dapp.category, dapp.icon, " +
			"it.dappId, " +
			"ot.dappId, ot.outTransactionId, " +
			"lower(hex(t.requesterPublicKey)), t.signatures " +
			"FROM blocks b " +
			"left outer join trs as t on t.blockId=b.id " +
			"left outer join delegates as d on d.transactionId=t.id " +
			"left outer join votes as v on v.transactionId=t.id " +
			"left outer join signatures as s on s.transactionId=t.id " +
			"left outer join contacts as c on c.transactionId=t.id " +
			"left outer join usernames as u on u.transactionId=t.id " +
			"left outer join multisignatures as m on m.transactionId=t.id " +
			"left outer join dapps as dapp on dapp.transactionId=t.id " +
			"left outer join intransfer it on it.transactionId=t.id " +
			"left outer join outtransfer ot on ot.transactionId=t.id " +
			"where b.height = (select max(height) from blocks) " +
			"ORDER BY b.height, t.rowid" +
			"", {}, privated.blocksDataFields, function (err, rows) {
			if (err) {
				return cb(err);
			}

			var block = privated.readDbRows(rows)[0];

			block.transactions = block.transactions.sort(function (a, b) {
				if (block.id == genesisblock.block.id) {
					if (a.type == TransactionTypes.VOTE)
						return 1;
				}

				if (a.type == TransactionTypes.SIGNATURE) {
					return 1;
				}

				return 0;
			});

			cb(null, block);
		});
	}, cb);
};

Blocks.prototype.getLastBlock = function () {
	return privated.lastBlock;
};

Blocks.prototype.processBlock = function (block, broadcast, cb) {
	if (!privated.loaded) {
		return setImmediate(cb, "Blockchain is loading");
	}
	privated.isActive = true;
	library.balancesSequence.add(function (cb) {
		try {
			block.id = library.logic.block.getId(block);
		} catch (e) {
			privated.isActive = false;
			return setImmediate(cb, e.toString());
		}
		block.height = privated.lastBlock.height + 1;

		modules.transactions.undoUnconfirmedList(function (err, unconfirmedTransactions) {
			if (err) {
				privated.isActive = false;
				return process.exit(0);
			}

			function done(err) {
				modules.transactions.applyUnconfirmedList(unconfirmedTransactions, function () {
					privated.isActive = false;
					setImmediate(cb, err);
				});
			}

			if (!block.previousBlock && block.height != 1) {
				return setImmediate(done, "Invalid previous block");
			}

			var expectedReward = privated.milestones.calcReward(block.height);

			if (block.height != 1 && expectedReward !== block.reward) {
				return setImmediate(done, "Invalid block reward");
			}

			library.dbLite.query("SELECT id FROM blocks WHERE id=$id", {id: block.id}, ['id'], function (err, rows) {
				if (err) {
					return done(err);
				}

				var bId = rows.length && rows[0].id;

				if (bId) {
					return done("Block already exists: " + block.id);
				}

				try {
					var valid = library.logic.block.verifySignature(block);
				} catch (e) {
					return setImmediate(cb, e.toString());
				}
				if (!valid) {
					return done("Can't verify signature: " + block.id);
				}

				if (block.previousBlock != privated.lastBlock.id) {
					// Fork same height and different previous block
					modules.delegates.fork(block, 1);
					return done("Can't verify previous block: " + block.id);
				}

				if (block.version > 0) {
					return done("Invalid block version: " + block.id);
				}

				var blockSlotNumber = slots.getSlotNumber(block.timestamp);
				var lastBlockSlotNumber = slots.getSlotNumber(privated.lastBlock.timestamp);

				if (blockSlotNumber > slots.getSlotNumber() || blockSlotNumber <= lastBlockSlotNumber) {
					return done("Can't verify block timestamp: " + block.id);
				}

				modules.delegates.validateBlockSlot(block, function (err) {
					if (err) {
						// Fork another delegate's slot
						modules.delegates.fork(block, 3);
						return done("Can't verify slot: " + block.id);
					}
					if (block.payloadLength > constants.maxPayloadLength) {
						return done("Can't verify payload length of block: " + block.id);
					}

					if (block.transactions.length != block.numberOfTransactions) {
						return done("Invalid amount of block assets: " + block.id);
					}

					// Check payload hash, transaction, number of confirmations

					var totalAmount = 0, totalFee = 0, payloadHash = crypto.createHash('sha256'), appliedTransactions = {}; // acceptedRequests = {}, acceptedConfirmations = {};

					async.eachSeries(block.transactions, function (transaction, cb) {
						try {
							transaction.id = library.logic.transaction.getId(transaction);
						} catch (e) {
							return setImmediate(cb, e.toString());
						}

						transaction.blockId = block.id;

						library.dbLite.query("SELECT id FROM trs WHERE id=$id", {id: transaction.id}, ['id'], function (err, rows) {
								if (err) {
									return cb(err);
								}

								var tId = rows.length && rows[0].id;

								if (tId) {
									// Fork transactions already exist
									modules.delegates.fork(block, 2);
									setImmediate(cb, "Transaction already exists: " + transaction.id);
								} else {
									if (appliedTransactions[transaction.id]) {
										return setImmediate(cb, "Duplicated transaction in block: " + transaction.id);
									}

									modules.accounts.getAccount({publicKey: transaction.senderPublicKey}, function (err, sender) {
										if (err) {
											return cb(err);
										}

										library.logic.transaction.verify(transaction, sender, function (err,sender) {
											if (err) {
												return setImmediate(cb, err);
											}

											modules.transactions.applyUnconfirmed(transaction, sender, function (err) {
												if (err) {
													return setImmediate(cb, "Failed to apply transaction: " + transaction.id);
												}

												try {
													var bytes = library.logic.transaction.getBytes(transaction);
												} catch (e) {
													return setImmediate(cb, e.toString());
												}

												appliedTransactions[transaction.id] = transaction;

												var index = unconfirmedTransactions.indexOf(transaction.id);
												if (index >= 0) {
													unconfirmedTransactions.splice(index, 1);
												}

												payloadHash.update(bytes);

												totalAmount += transaction.amount;
												totalFee += transaction.fee;

												setImmediate(cb);
											});
										});
									});
								}
							}
						);
					}, function (err) {
						var errors = [];

						if (err) {
							errors.push(err);
						}

						if (payloadHash.digest().toString('hex') !== block.payloadHash) {
							errors.push("Invalid payload hash: " + block.id);
						}

						if (totalAmount != block.totalAmount) {
							errors.push("Invalid total amount: " + block.id);
						}

						if (totalFee != block.totalFee) {
							errors.push("Invalid total fee: " + block.id);
						}

						if (errors.length > 0) {
							async.eachSeries(block.transactions, function (transaction, cb) {
								if (appliedTransactions[transaction.id]) {
									modules.transactions.undoUnconfirmed(transaction, cb);
								} else {
									setImmediate(cb);
								}
							}, function () {
								done(errors[0]);
							});
						} else {
							try {
								block = library.logic.block.objectNormalize(block);
							} catch (e) {
								return setImmediate(done, e);
							}

							async.eachSeries(block.transactions, function (transaction, cb) {
								modules.accounts.setAccountAndGet({publicKey: transaction.senderPublicKey}, function (err, sender) {
									if (err) {
										library.logger.error("Failed to apply transactions: " + transaction.id);
										process.exit(0);
									}
									modules.transactions.apply(transaction, block, sender, function (err) {
										if (err) {
											library.logger.error("Failed to apply transactions: " + transaction.id);
											process.exit(0);
										}
										modules.transactions.removeUnconfirmedTransaction(transaction.id);
										setImmediate(cb);
									});
								});
							}, function (err) {
								privated.saveBlock(block, function (err) {
									if (err) {
										library.logger.error("Failed to save block...");
										library.logger.error(err);
										process.exit(0);
									}

									library.bus.message('newBlock', block, broadcast);
									privated.lastBlock = block;

									modules.round.tick(block, done);
									// setImmediate(done);
								});
							});
						}
					});
				});
			});
		});
	}, cb);
};

Blocks.prototype.simpleDeleteAfterBlock = function (blockId, cb) {
	library.dbLite.query("DELETE FROM blocks WHERE height >= (SELECT height FROM blocks where id = $id)", {id: blockId}, cb);
};

Blocks.prototype.loadBlocksFromPeer = function (peer, lastCommonBlockId, cb) {
	var loaded = false;
	var count = 0;
	var lastValidBlock = null;

	async.whilst(
		function () {
			return !loaded && count < 30;
		},
		function (next) {
			count++;
			modules.transport.getFromPeer(peer, {
				method: "GET",
				api: '/blocks?lastBlockId=' + lastCommonBlockId
			}, function (err, data) {
				if (err || data.body.error) {
					return next(err || data.body.error.toString());
				}

				var blocks = data.body.blocks;

				if (typeof blocks === "string") {
					blocks = library.dbLite.parseCSV(blocks);
				}

				var report = library.scheme.validate(blocks, {
					type: "array"
				});

				if (!report) {
					return next("Error, can't parse blocks...");
				}

				blocks = blocks.map(library.dbLite.row2parsed, library.dbLite.parseFields(privated.blocksDataFields));
				blocks = privated.readDbRows(blocks);

				if (blocks.length === 0) {
					loaded = true;
					next();
				} else {
					async.eachSeries(blocks, function (block, cb) {
						try {
							block = library.logic.block.objectNormalize(block);
						} catch (e) {
							var peerStr = data.peer ? ip.fromLong(data.peer.ip) + ":" + data.peer.port : 'unknown';
							library.logger.log('Block ' + (block ? block.id : 'null') + ' is not valid, ban 60 min', peerStr);
							modules.peer.state(peer.ip, peer.port, 0, 3600);
							return setImmediate(cb, e);
						}
						self.processBlock(block, false, function (err) {
							if (!err) {
								lastCommonBlockId = block.id;
								lastValidBlock = block;
							} else {
								var peerStr = data.peer ? ip.fromLong(data.peer.ip) + ":" + data.peer.port : 'unknown';
								library.logger.log('Block ' + (block ? block.id : 'null') + ' is not valid, ban 60 min', peerStr);
								modules.peer.state(peer.ip, peer.port, 0, 3600);
							}

							setImmediate(cb, err);
						});
					}, next);
				}
			});
		},
		function (err) {
			setImmediate(cb, err, lastValidBlock);
		}
	);
};

Blocks.prototype.deleteBlocksBefore = function (block, cb) {
	var blocks = [];

	async.whilst(
		function () {
			return !(block.height >= privated.lastBlock.height);
		},
		function (next) {
			blocks.unshift(privated.lastBlock);
			privated.popLastBlock(privated.lastBlock, function (err, newLastBlock) {
				privated.lastBlock = newLastBlock;
				next(err);
			});
		},
		function (err) {
			setImmediate(cb, err, blocks);
		}
	);
};

Blocks.prototype.generateBlock = function (keypair, timestamp, cb) {
	var transactions = modules.transactions.getUnconfirmedTransactionList();
	var ready = [];

	async.eachSeries(transactions, function (transaction, cb) {
		modules.accounts.getAccount({publicKey: transaction.senderPublicKey}, function (err, sender) {
			if (err || !sender) {
				return cb("Invalid sender");
			}

			if (library.logic.transaction.ready(transaction, sender)) {
				library.logic.transaction.verify(transaction, sender, function (err) {
					ready.push(transaction);
					cb();
				});
			} else {
				setImmediate(cb);
			}
		});
	}, function () {
		try {
			var block = library.logic.block.create({
				keypair: keypair,
				timestamp: timestamp,
				previousBlock: privated.lastBlock,
				transactions: ready
			});
		} catch (e) {
			return setImmediate(cb, e);
		}

		self.processBlock(block, true, cb);
	});
};

Blocks.prototype.sandboxApi = function (call, args, cb) {
	sandboxHelper.callMethod(shared, call, args, cb);
};

// Events
Blocks.prototype.onReceiveBlock = function (block) {
	if (modules.loader.syncing() || !privated.loaded) {
		return;
	}

	library.sequence.add(function (cb) {
		if (block.previousBlock == privated.lastBlock.id && privated.lastBlock.height + 1 == block.height) {
			library.logger.log('Recieved new block id: ' + block.id + ' height: ' + block.height + ' slot: ' + slots.getSlotNumber(block.timestamp) + ' reward: ' + modules.blocks.getLastBlock().reward);
			self.processBlock(block, true, cb);
		} else if (block.previousBlock != privated.lastBlock.id && privated.lastBlock.height + 1 == block.height) {
			// Fork right height and different previous block
			modules.delegates.fork(block, 1);
			cb("Fork");
		} else if (block.previousBlock == privated.lastBlock.previousBlock && block.height == privated.lastBlock.height && block.id != privated.lastBlock.id) {
			// Fork same height and same previous block, but different block id
			modules.delegates.fork(block, 4);
			cb("Fork");
		} else {
			cb();
		}
	});
};

Blocks.prototype.onBind = function (scope) {
	modules = scope;

	privated.loaded = true;
};

Blocks.prototype.cleanup = function (cb) {
	privated.loaded = false;
	if (!privated.isActive) {
		cb();
	} else {
		setImmediate(function nextWatch() {
			if (privated.isActive) {
				setTimeout(nextWatch, 1 * 1000);
			} else {
				cb();
			}
		});
	}
};


shared.getBlocks = function (req, cb) {
	if (!privated.loaded) {
		cb("Blockchain is loading");
	}
	var query = req.body;
	library.scheme.validate(query, {
		type: "object",
		properties: {
			ID: {
				type: "string"
			},
			PREVIOUS_BLOCK: {
				type: "string"
			},
			start: {
				type: "integer",
				minimum: 0
			},
			limit: {
				type: "integer",
				minimum: 0,
				maximum: 100
			}
		}
	}, function (err) {
		if (err) {
			return cb(err[0].message);
		}

		library.dbSequence.add(function (cb) {
			privated.list(query, function (err, data) {
				if (err) {
					return cb("Database error");
				}
				cb(null, {BLOCKS: data.blocks, TOTAL: data.count});
			});
		}, cb);
	});
};

// Export
module.exports = Blocks;
