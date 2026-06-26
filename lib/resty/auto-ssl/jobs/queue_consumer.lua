local lock = require "resty.lock"
local ssl_provider = require "resty.auto-ssl.ssl_providers.lets_encrypt"

local _M = {}

-- Based on lua-resty-upstream-healthcheck's lock (same approach as the renewal
-- job): ensures the consumer only runs once per interval across all workers.
local function get_interval_lock(name, interval)
  local key = "lock:" .. name
  local ok, err = ngx.shared.auto_ssl:add(key, true, interval - 0.001)
  if not ok then
    if err == "exists" then
      return nil
    end
    ngx.log(ngx.ERR, "auto-ssl: failed to add key \"", key, "\": ", err)
    return nil
  end
  return true
end

local function process_domain_unlock(domain, storage, local_lock, distributed_lock_value)
  if local_lock then
    local _, local_unlock_err = local_lock:unlock()
    if local_unlock_err then
      ngx.log(ngx.ERR, "auto-ssl: failed to unlock: ", local_unlock_err)
    end
  end

  if distributed_lock_value then
    local _, distributed_unlock_err = storage:issue_cert_unlock(domain, distributed_lock_value)
    if distributed_unlock_err then
      ngx.log(ngx.ERR, "auto-ssl: failed to unlock: ", distributed_unlock_err)
    end
  end
end

-- Record a failed issuance and compute the next attempt time using the
-- configured backoff schedule (the last entry is the cap).
local function record_failure(auto_ssl_instance, storage, domain, previous_fails)
  local schedule = auto_ssl_instance:get("cert_backoff_schedule")
  local fails = (previous_fails or 0) + 1
  local idx = fails
  if idx > #schedule then
    idx = #schedule
  end
  local delay = schedule[idx]
  local next_attempt = ngx.now() + delay

  -- Expire the backoff state a bit after the next attempt so stale entries
  -- don't linger, but it always outlives the wait itself.
  local _, set_err = storage:set_backoff(domain, fails, next_attempt, delay + 600)
  if set_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to set backoff for ", domain, ": ", set_err)
  end
  ngx.log(ngx.NOTICE, "auto-ssl: issuance failed for ", domain, " (failure ", fails, "), next attempt in ", delay, "s")
end

-- Returns true if a certificate was successfully issued this call.
local function process_domain(auto_ssl_instance, storage, domain)
  -- Skip domains that are in a backoff window from previous failures.
  local backoff, backoff_err = storage:get_backoff(domain)
  if backoff_err then
    ngx.log(ngx.ERR, "auto-ssl: error reading backoff for ", domain, ": ", backoff_err)
  end
  if backoff and backoff["next_attempt"] and backoff["next_attempt"] > ngx.now() then
    return false
  end

  -- Local lock so multiple workers in this instance don't issue the same cert.
  local local_lock, new_local_lock_err = lock:new("auto_ssl", { exptime = 30, timeout = 30 })
  if new_local_lock_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create lock: ", new_local_lock_err)
    return false
  end
  local _, local_lock_err = local_lock:lock("issue_cert:" .. domain)
  if local_lock_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to obtain lock: ", local_lock_err)
    return false
  end

  -- Distributed lock across instances (shares the issuance lock used by the
  -- on-demand and renewal paths).
  local distributed_lock_value, distributed_lock_err = storage:issue_cert_lock(domain)
  if distributed_lock_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to obtain lock: ", distributed_lock_err)
    process_domain_unlock(domain, storage, local_lock, nil)
    return false
  end

  -- If the certificate already exists (issued elsewhere, or a leftover queue
  -- entry), drop it from the queue and clear any backoff.
  local cert, get_cert_err = storage:get_cert(domain)
  if get_cert_err then
    ngx.log(ngx.ERR, "auto-ssl: error fetching certificate from storage for ", domain, ": ", get_cert_err)
  end
  if cert and cert["fullchain_pem"] and cert["privkey_pem"] then
    storage:remove_pending_domain(domain)
    storage:delete_backoff(domain)
    process_domain_unlock(domain, storage, local_lock, distributed_lock_value)
    return false
  end

  -- Only issue for domains still allowed. A disallowed domain is dropped from
  -- the queue rather than retried.
  local allow_domain = auto_ssl_instance:get("allow_domain")
  if not allow_domain(domain, auto_ssl_instance, nil, false) then
    ngx.log(ngx.NOTICE, "auto-ssl: domain not allowed, dropping from queue: ", domain)
    storage:remove_pending_domain(domain)
    storage:delete_backoff(domain)
    process_domain_unlock(domain, storage, local_lock, distributed_lock_value)
    return false
  end

  ngx.log(ngx.NOTICE, "auto-ssl: issuing queued certificate for ", domain)
  local issued_cert, issue_err = ssl_provider.issue_cert(auto_ssl_instance, domain)

  local success = false
  if issue_err or not issued_cert then
    record_failure(auto_ssl_instance, storage, domain, backoff and backoff["fails"])
  else
    storage:remove_pending_domain(domain)
    storage:delete_backoff(domain)
    success = true
  end

  process_domain_unlock(domain, storage, local_lock, distributed_lock_value)
  return success
end

local function consume_queue(auto_ssl_instance)
  local storage = auto_ssl_instance.storage
  local domains, domains_err = storage:get_pending_domains()
  if domains_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to fetch pending cert domains: ", domains_err)
    return
  end
  if not domains or #domains == 0 then
    return
  end

  local issue_max = auto_ssl_instance:get("queue_issue_max")
  local issued = 0
  -- Process sequentially so we issue one certificate at a time.
  for _, domain in ipairs(domains) do
    if process_domain(auto_ssl_instance, storage, domain) then
      issued = issued + 1
      if issued >= issue_max then
        ngx.log(ngx.NOTICE, "auto-ssl: reached queue_issue_max (", issue_max, ") this cycle")
        break
      end
    end
  end
end

local function do_consume(auto_ssl_instance)
  -- Ensure only 1 worker runs the consumer per interval.
  if not get_interval_lock("queue_consumer", auto_ssl_instance:get("queue_consumer_interval")) then
    return
  end
  local consumer_lock, new_lock_err = lock:new("auto_ssl_settings", { exptime = 1800, timeout = 0 })
  if new_lock_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to create lock: ", new_lock_err)
    return
  end
  local _, lock_err = consumer_lock:lock("queue_consumer")
  if lock_err then
    ngx.log(ngx.ERR, "auto-ssl: failed to obtain lock: ", lock_err)
    return
  end

  local consume_ok, consume_err = pcall(consume_queue, auto_ssl_instance)
  if not consume_ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to run queue consumer cycle: ", consume_err)
  end

  local ok, unlock_err = consumer_lock:unlock()
  if not ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to unlock: ", unlock_err)
  end
end

local function consume(premature, auto_ssl_instance)
  if premature then return end

  local consume_ok, consume_err = pcall(do_consume, auto_ssl_instance)
  if not consume_ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to run do_consume cycle: ", consume_err)
  end

  local timer_ok, timer_err = ngx.timer.at(auto_ssl_instance:get("queue_consumer_interval"), consume, auto_ssl_instance)
  if not timer_ok then
    if timer_err ~= "process exiting" then
      ngx.log(ngx.ERR, "auto-ssl: failed to create timer: ", timer_err)
    end
    return
  end
end

function _M.spawn(auto_ssl_instance)
  local ok, err = ngx.timer.at(auto_ssl_instance:get("queue_consumer_interval"), consume, auto_ssl_instance)
  if not ok then
    ngx.log(ngx.ERR, "auto-ssl: failed to create queue consumer timer: ", err)
    return
  end
end

return _M
