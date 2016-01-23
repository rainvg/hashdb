'use strict';

var sqlite3 = require("sqlite3").verbose();
var crypto = require('crypto');
var fs = require('fs');

function hashdb(path)
{
  // Constructor

  var _path = path;
  var _new = !fs.existsSync(_path);
  var _db = new sqlite3.Database(_path);

  if(_new)
  {
    _db.serialize(function()
    {
      _db.run("begin");
      _db.run("create table `items` (`idx` bigint unique, `merkle` char(64), `tag` text unique, `digest` char(64))");
      _db.run("create table `updates` (`version` integer primary key autoincrement, `remove` tinyint(1), `tag` text, `digest` char(64))");
      _db.run("commit");
    });
  }

  // Getters

  var __path__ = this.path = function() // jshint ignore: line
  {
    return _path;
  };

  var __root__ = this.root = function() // jshint ignore: line
  {
    return new Promise(function(resolve, reject)
    {
      _db.get("select `merkle` from items where `idx` = 1", function(error, response)
      {
        if(error) {reject(error); return;}
        if(!response) {resolve("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); return;}
        resolve(response.merkle);
      });
    });
  };

  var __version__ = this.version = function() // jshint ignore: line
  {
    return new Promise(function(resolve, reject)
    {
      _db.get("select max(`version`) as version from updates", function(error, response)
      {
        if(error) {reject(error); return;}
        if(!response.version) {resolve(0); return;}
        resolve(response.version);
      });
    });
  };

  // Private methods

  var __compute_merkle__ = function(item)
  {
    var sha256 = crypto.createHash("sha256");
    sha256.update(item.tag);
    sha256.update(item.digest);
    var data = sha256.digest("hex");

    sha256 = crypto.createHash("sha256");
    sha256.update(data);
    sha256.update(item.left_merkle);
    sha256.update(item.right_merkle);

    return sha256.digest("hex");
  };

  var __update_merkle__ = function(idx)
  {
    if(idx === 0)
      return Promise.resolve();
    else
    {
      return new Promise(function(resolve, reject)
      {
        _db.get("select parent.`tag` as tag, parent.`digest` as digest, coalesce(left.`merkle`, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') as left_merkle, coalesce(right.`merkle`, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') as right_merkle from items as parent left join items as left on left.`idx` = 2 * parent.`idx` left join items as right on right.`idx` = 2 * parent.`idx` + 1 where parent.`idx` = ?", idx, function(error, response)
        {
          if(error || !response) {reject(error);}

          _db.run("update items set merkle = ? where idx = ?", __compute_merkle__(response), idx, function(error)
          {
            if(error) {reject(error); return;}
            resolve();
          });
        });
      }).then(function()
      {
        return __update_merkle__(Math.floor(idx / 2));
      });
    }
  };

  // Methods

  var __add__ = this.add = function(tag, digest) //jshint ignore: line
  {
    var idx;

    return new Promise(function(resolve, reject)
    {
      _db.serialize(function()
      {
        try
        {
          _db.run("begin");
          _db.run("insert into updates values (null, 0, ?, ?)", tag, digest);

          _db.get("select count(*) as count from items", function(error, response)
          {
            if(error) {reject(error); return;}

            idx = response.count + 1;

            _db.run("insert into items values (?, null, ?, ?)", idx, tag, digest, function(error)
            {
              if(error) {reject(error); return;}
              resolve();
            });
          });
        } catch(error) {reject(error);}
      });
    }).then(function()
    {
      return __update_merkle__(idx);
    }).then(function()
    {
      return new Promise(function(resolve, reject)
      {
        _db.run("commit", function(error)
        {
          if(error) {reject(error); return;}
          resolve();
        });
      });
    }).catch(function(error)
    {
      _db.run("rollback");
      return Promise.reject(error);
    });
  };

  var __remove__ = this.remove = function(tag) // jshint ignore: line
  {
    var remidx;
    var movidx;

    return new Promise(function(resolve, reject)
    {
      _db.serialize(function()
      {
        try
        {
          _db.run("begin");
          _db.run("insert into updates values(null, 1, ?, null)");

          _db.get("select rem.`idx` as remidx, max(mov.`idx`) as movidx from items as rem, items as mov where rem.tag = ?", tag, function(error, response)
          {
            if(error || !response) {reject(error);}

            remidx = response.remidx;
            movidx = response.movidx;

            _db.run("delete from items where idx = ?", remidx, function(error)
            {
              if(error) {reject(error); return;}

              if(remidx !== movidx)
              {
                _db.run("update items set idx = ? where idx = ?", remidx, movidx, function(error)
                {
                  if(error) {reject(error); return;}
                  resolve();
                });
                return;
              }

              resolve();
            });
          });
        } catch (error) {reject(error);}
      });
    }).then(function()
    {
      return __update_merkle__(Math.floor(movidx / 2));
    }).then(function()
    {
      if(remidx !== movidx)
        return __update_merkle__(remidx);
    }).then(function()
    {
      return new Promise(function(resolve, reject)
      {
        _db.run("commit", function(error)
        {
          if(error) {reject(error); return;}
          resolve();
        });
      });
    }).catch(function(error)
    {
      _db.run("rollback");
      return Promise.reject(error);
    });
  };

  var __prove__ = this.prove = function(tag) // jshint ignore: line
  {
    var proof = [];

    return new Promise(function(resolve, reject)
    {
      function __recursion__(idx)
      {
        if(idx === 0) {resolve(proof); return;}
        else
        {
          _db.get("select parent.`tag` as tag, parent.`digest` as digest, coalesce(left.`merkle`, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') as left_merkle, coalesce(right.`merkle`, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') as right_merkle from items as parent left join items as left on left.`idx` = 2 * parent.`idx` left join items as right on right.`idx` = 2 * parent.`idx` + 1 where parent.`idx` = ?", idx, function(error, response)
          {
            if(error || !response) {reject(error);}

            proof.push({tag: response.tag, digest: response.digest, left_merkle: response.left_merkle, right_merkle: response.right_merkle});
            __recursion__(Math.floor(idx / 2));
          });
        }
      }

      _db.get("select idx from items where tag = ?", tag, function(error, response)
      {
        if(error || !response) {reject(error); return;}
        __recursion__(response.idx);
      });
    });
  };
}

function check(root, proof)
{
  var merkle = null;

  for(var i in proof)
  {
    if(merkle && merkle !== proof[i].left_merkle && merkle !== proof[i].right_merkle)
      return false;

    merkle = __compute_merkle__(proof[i]); // jshint ignore:line
  }

  return root === merkle;
}

module.exports = {
  hashdb: hashdb,
  check: check
};
