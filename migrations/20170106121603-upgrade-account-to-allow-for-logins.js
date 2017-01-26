var dbm = require('db-migrate');
var type = dbm.dataType;
var async = require('async');

exports.up = function(db, callback) {
    db.runSql("ALTER TABLE  `account`"
    + "ADD `last_login`  BIGINT(13) NULL DEFAULT NULL,"
    + "ADD `active` BOOLEAN DEFAULT 1,"
    + "ADD `passwd` VARCHAR(255),"
    + "ADD `salt` TINYBLOB, "
    + "ADD `created_at` BIGINT( 13 ) NULL DEFAULT NULL,"
    + "ADD `updated_at` BIGINT( 13 ) NULL DEFAULT NULL;", callback);
};

exports.down = function(db, callback) {
  db.runSql("ALTER TABLE `account` DROP `last_login`, DROP `active`, DROP `passwd`, DROP `salt`, DROP `created_at`, DROP `updated_at`", callback);
};
