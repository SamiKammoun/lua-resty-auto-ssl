local random_seed = require "resty.auto-ssl.utils.random_seed"
local renewal_job = require "resty.auto-ssl.jobs.renewal"
local queue_consumer_job = require "resty.auto-ssl.jobs.queue_consumer"
local shell_blocking = require "shell-games"
local start_sockproc = require "resty.auto-ssl.utils.start_sockproc"

return function(auto_ssl_instance)
  local renewals_enabled = auto_ssl_instance:get("renewals_enabled")
  local queue_consumer_enabled = auto_ssl_instance:get("queue_consumer_enabled")

  -- Issuance (via dehydrated/sockproc) only happens on this instance if it
  -- renews certificates or drains the generation queue. renewals_enabled
  -- defaults to true, so default deployments (including on-demand issuance via
  -- generate_certs in the handshake) keep the issuance machinery as before.
  -- Instances that only serve certificates set both flags false, so no
  -- dehydrated process ever runs there.
  local issuance_enabled = renewals_enabled or queue_consumer_enabled

  local base_dir = auto_ssl_instance:get("dir")

  -- random_seed was called during the "init" master phase, but we want to
  -- ensure each worker process's random seed is different, so force another
  -- call in the init_worker phase.
  random_seed()

  if issuance_enabled then
    local _, mkdir_challenges_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/letsencrypt/.acme-challenges" }, { umask = "0022" })
    if mkdir_challenges_err then
      ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt/.acme-challenges dir: ", mkdir_challenges_err)
    end
    local _, mkdir_locks_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/letsencrypt/locks" }, { umask = "0022" })
    if mkdir_locks_err then
      ngx.log(ngx.ERR, "auto-ssl: failed to create letsencrypt/locks dir: ", mkdir_locks_err)
    end

    -- Startup sockproc. This background process allows for non-blocking shell
    -- commands with resty.shell.
    --
    -- We do this in the init_worker phase, so that it will always be started
    -- with the same permissions as the nginx workers (and not the elevated
    -- permissions of the nginx master process).
    --
    -- If we implement a native resty Let's Encrypt ACME client (rather than
    -- relying on dehydrated), then we could get rid of the need for this
    -- background process, which would be nice.
    start_sockproc()
  end

  local storage = auto_ssl_instance.storage
  local storage_adapter = storage.adapter
  if storage_adapter.setup_worker then
    storage_adapter:setup_worker()
  end

  if renewals_enabled then
    renewal_job.spawn(auto_ssl_instance)
  end

  if queue_consumer_enabled then
    -- One-time domain index backfill (single worker), so renewal discovery via
    -- the index has the pre-existing certificates. Uses SCAN, never KEYS.
    if auto_ssl_instance:get("use_domain_index") and ngx.worker.id() == 0 then
      local ok, backfill_err = ngx.timer.at(0, function(premature)
        if premature then return end
        local count, build_err = storage:build_domain_index()
        if build_err then
          ngx.log(ngx.ERR, "auto-ssl: domain index backfill failed: ", build_err)
        else
          ngx.log(ngx.NOTICE, "auto-ssl: domain index backfill added ", count, " domains")
        end
      end)
      if not ok then
        ngx.log(ngx.ERR, "auto-ssl: failed to schedule domain index backfill: ", backfill_err)
      end
    end

    queue_consumer_job.spawn(auto_ssl_instance)
  end
end
