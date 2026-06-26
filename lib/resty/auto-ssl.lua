-- Ensure resty.core FFI libraries are loaded to prevent potential deadlocks in
-- shdict. These are loaded by default in OpenResty 1.15.8.1+, but this will
-- ensure this library is loaded in older versions.
--
-- https://github.com/openresty/lua-nginx-module/issues/1207#issuecomment-350742782
-- https://github.com/auto-ssl/lua-resty-auto-ssl/issues/43
-- https://github.com/auto-ssl/lua-resty-auto-ssl/issues/220
require "resty.core"

local _M = {}

local current_file_path = package.searchpath("resty.auto-ssl", package.path)
_M.lua_root = string.match(current_file_path, "(.*)/.*/.*/.*/.*/.*")
if string.sub(_M.lua_root, 1, 2) == "./" then
  local lfs = require "lfs"
  _M.lua_root = lfs.currentdir() .. string.sub(_M.lua_root, 2, -1)
end

function _M.new(options)
  if not options then
    options = {}
  end

  if not options["dir"] then
    options["dir"] = "/etc/resty-auto-ssl"
  end

  if not options["request_domain"] then
    options["request_domain"] = function(ssl, ssl_options) -- luacheck: ignore
      return ssl.server_name()
    end
  end

  if not options["allow_domain"] then
    options["allow_domain"] = function(domain, auto_ssl, ssl_options, renewal) -- luacheck: ignore
      return false
    end
  end

  if not options["storage_adapter"] then
    options["storage_adapter"] = "resty.auto-ssl.storage_adapters.file"
  end

  if not options["json_adapter"] then
    options["json_adapter"] = "resty.auto-ssl.json_adapters.cjson"
  end

  if not options["ocsp_stapling_error_level"] then
    options["ocsp_stapling_error_level"] = ngx.ERR
  end

  if not options["renew_check_interval"] then
    options["renew_check_interval"] = 86400 -- 1 day
  end

  if not options["hook_server_port"] then
    options["hook_server_port"] = 8999
  end

  if not options["renew_cnt_eachtime"] then
    options["renew_cnt_eachtime"] = 20 -- number of domains each checking time
  end

  -- Whether the renewal background job is spawned in init_worker. Set to false
  -- on instances that should only serve certificates (not renew them), so a
  -- single dedicated instance can own renewals.
  if options["renewals_enabled"] == nil then
    options["renewals_enabled"] = true
  end

  -- When true, a handshake for an allowed domain with no certificate (and with
  -- generate_certs disabled) records the domain in a redis set instead of
  -- issuing inline. A separate instance running the queue consumer issues it.
  if options["queue_missing_certs"] == nil then
    options["queue_missing_certs"] = false
  end

  -- Redis set holding domains that need a certificate generated.
  if not options["cert_queue_key"] then
    options["cert_queue_key"] = "auto_ssl:pending_domains"
  end

  -- shared dict used to throttle repeat enqueues of the same domain per worker
  -- process, so the hot handshake path doesn't hammer redis. If the dict does
  -- not exist, throttling is skipped (every miss enqueues).
  if not options["queue_throttle_dict"] then
    options["queue_throttle_dict"] = "cert_queue_throttle"
  end
  if not options["queue_throttle_seconds"] then
    options["queue_throttle_seconds"] = 300
  end

  -- Whether this instance runs the background job that drains the cert queue
  -- and issues certificates. Should be enabled on exactly one instance.
  if options["queue_consumer_enabled"] == nil then
    options["queue_consumer_enabled"] = false
  end
  if not options["queue_consumer_interval"] then
    options["queue_consumer_interval"] = 60
  end

  -- Maximum number of certificates successfully issued per queue consumer
  -- cycle, to keep cycles bounded and stay within ACME rate limits.
  if not options["queue_issue_max"] then
    options["queue_issue_max"] = 25
  end

  -- Key prefix for per-domain issuance backoff state (stored in the storage
  -- adapter so it survives restarts and is shared across instances).
  if not options["cert_backoff_prefix"] then
    options["cert_backoff_prefix"] = "auto_ssl:cert_backoff:"
  end

  -- Backoff schedule (seconds) applied after consecutive issuance failures for
  -- a domain. The last value is the cap.
  if not options["cert_backoff_schedule"] then
    options["cert_backoff_schedule"] = { 60, 300, 1800, 7200, 21600 }
  end

  -- When true, renewal discovery reads the domain index set instead of scanning
  -- the keyspace (KEYS *:latest), which is dangerous on large/shared redis.
  if options["use_domain_index"] == nil then
    options["use_domain_index"] = false
  end

  -- Redis set holding every domain that has a stored certificate. Maintained by
  -- set_cert when use_domain_index is on, and used for renewal discovery.
  if not options["domain_index_key"] then
    options["domain_index_key"] = "auto_ssl:cert_domains"
  end

  return setmetatable({ options = options }, { __index = _M })
end

function _M.set(self, key, value)
  if key == "storage" then
    ngx.log(ngx.ERR, "auto-ssl: DEPRECATED: Don't use auto_ssl:set() for the 'storage' instance. Set directly with auto_ssl.storage.")
    self.storage = value
    return
  end

  self.options[key] = value
end

function _M.get(self, key)
  if key == "storage" then
    ngx.log(ngx.ERR, "auto-ssl: DEPRECATED: Don't use auto_ssl:get() for the 'storage' instance. Get directly with auto_ssl.storage.")
    return self.storage
  end

  return self.options[key]
end

function _M.init(self)
  local init_master = require "resty.auto-ssl.init_master"
  init_master(self)
end

function _M.init_worker(self)
  local init_worker = require "resty.auto-ssl.init_worker"
  init_worker(self)
end

function _M.ssl_certificate(self, ssl_options)
  local ssl_certificate = require "resty.auto-ssl.ssl_certificate"
  ssl_certificate(self, ssl_options)
end

function _M.challenge_server(self)
  local server = require "resty.auto-ssl.servers.challenge"
  server(self)
end

function _M.has_certificate(self, domain, shmem_only)
  local has_certificate = require "resty.auto-ssl.utils.has_certificate"
  return has_certificate(self, domain, shmem_only)
end

function _M.hook_server(self)
  local server = require "resty.auto-ssl.servers.hook"
  server(self)
end

return _M
