require 'json'
require 'digest'
require 'fileutils'
require 'open3'
require 'etc'

OUT = '/out'.freeze
FIXTURE = '/tmp/b0-writer-fence'.freeze
SERVICES = ['puma', 'sidekiq'].freeze
RUBY = '/opt/gitlab/embedded/bin/ruby'.freeze
SV = '/opt/gitlab/embedded/bin/sv'.freeze
RUNSV = '/opt/gitlab/embedded/bin/runsv'.freeze
WRAPPER = '/opt/gitlab/bin/gitlab-rails'.freeze
report = {'schema' => 'b0-fixed-image-writer-fence-probe-v1', 'checks' => {},
          'commands' => [], 'observations' => {}, 'original_application_booted' => false,
          'business_actions' => 0, 'fixture_only' => true, 'service_processes' => []}

def run_record(report, name, command, environment = {})
  out, err, status = Open3.capture3(environment, *command)
  row = {'name' => name, 'command' => command, 'exit_code' => status.exitstatus,
         'stdout' => out, 'stderr' => err}
  report['commands'] << row
  row
end

def wait_until(seconds)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
  loop do
    return true if yield
    return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
    sleep 0.05
  end
end

supervisors = []
begin
  raise 'root_entry_required' unless Process.uid == 0
  FileUtils.mkdir_p([OUT, FIXTURE])
  wrapper = File.binread(WRAPPER)
  File.binwrite(OUT + '/gitlab-rails.original.txt', wrapper)
  report['wrapper_sha256'] = Digest::SHA256.hexdigest(wrapper)
  report['checks']['wrapper_has_supported_no_privilege_drop'] = wrapper.include?('NO_PRIVILEGE_DROP')
  raise 'expected_wrapper_option_absent' unless report['checks']['wrapper_has_supported_no_privilege_drop']
  rc = wrapper[/gitlab_rails_rc=['"]([^'"]+)['"]/, 1]
  raise 'fixed_wrapper_rc_path_unrecognized' unless rc && rc.start_with?('/opt/gitlab/etc/')
  report['fixture_rc_path'] = rc
  report['fixture_rc_preexisted'] = File.exist?(rc)
  # The pristine image need not have its configured service account yet.
  # Record explicitly if this disposable fixture supplies that account.
  begin
    account = Etc.getpwnam('git')
    report['git_account_created_for_fixture'] = false
  rescue ArgumentError
    result = run_record(report, 'create_fixture_git_account',
      ['/usr/sbin/useradd', '--system', '--user-group', '--home-dir', '/tmp/b0-git-home', '--no-create-home', 'git'])
    raise 'fixture_account_creation_failed' unless result['exit_code'] == 0
    account = Etc.getpwnam('git')
    report['git_account_created_for_fixture'] = true
  end
  group = Etc.getgrgid(account.gid).name
  report['git_account'] = {'uid' => account.uid, 'gid' => account.gid, 'group' => group}
  FileUtils.mkdir_p(File.dirname(rc))
  File.write(rc, "gitlab_user=git\ngitlab_group=#{group}\n")
  File.chmod(0o644, rc)
  envdir = '/opt/gitlab/etc/gitlab-rails/env'
  FileUtils.mkdir_p(envdir)
  File.chmod(0o755, envdir)
  # chpst reloads this after the wrapper intentionally unsets BUNDLE_GEMFILE.
  # Bundler evaluates the hook under exactly the wrapper-selected identity.
  gemfile = FIXTURE + '/Gemfile'
  File.write(gemfile, "load '/probe/observer.rb'\nexit 0\n")
  File.write(envdir + '/BUNDLE_GEMFILE', gemfile + "\n")
  File.chmod(0o644, gemfile)
  File.chmod(0o644, envdir + '/BUNDLE_GEMFILE')
  report['boot_hook_sha256'] = Digest::SHA256.file(gemfile).hexdigest
  report['boot_hook_scope'] = 'actual packaged wrapper and chpst; replaces Bundler application boot only in disposable fixture'

  SERVICES.each do |service|
    path = '/opt/gitlab/sv/' + service
    link = '/opt/gitlab/service/' + service
    raise 'fixture_service_path_already_exists' if File.exist?(path) || File.symlink?(path) || File.exist?(link) || File.symlink?(link)
    FileUtils.mkdir_p([path, File.dirname(link)])
    File.symlink(path, link)
    File.write(path + '/run', "#!/bin/sh\nexec #{RUBY} -e '$0=\"#{service} b0-writer-fixture\"; sleep 300'\n")
    File.chmod(0o755, path + '/run')
    pid = Process.spawn(RUNSV, path, out: OUT + '/' + service + '.supervisor.log', err: [:child, :out])
    supervisors << [service, pid]
    ready = wait_until(10) do
      status = File.binread(path + '/supervise/status') rescue ''
      status.bytesize == 20 && status.getbyte(19) == 1 && status.byteslice(12, 4).unpack1('V') > 0
    end
    raise 'fixture_service_not_running' unless ready
    File.chmod(0o755, path + '/supervise')
    proc_status = File.read("/proc/#{pid}/status")
    report['service_processes'] << {'service' => service, 'supervisor_pid' => pid,
      'fixture_service_path' => path, 'run_sha256' => Digest::SHA256.file(path + '/run').hexdigest,
      'supervisor_uids' => proc_status[/^Uid:\s+(.+)$/, 1].split.map(&:to_i),
      'supervisor_gids' => proc_status[/^Gid:\s+(.+)$/, 1].split.map(&:to_i)}
  end

  ['active', 'stopped'].each do |phase|
    if phase == 'stopped'
      SERVICES.each do |service|
        r = run_record(report, 'stop_fixture_' + service, [SV, '-w', '10', 'down', '/opt/gitlab/sv/' + service])
        raise 'fixture_stop_failed' unless r['exit_code'] == 0
      end
    end
    [['default', nil], ['retain_root', '1']].each do |mode, option|
      name = phase + '_' + mode
      r = run_record(report, name, [WRAPPER, 'runner', '0'],
        {'NO_PRIVILEGE_DROP' => option, 'B0_PROBE_NAME' => name})
      marker = r['stdout'].lines.find { |line| line.start_with?('B0_WRITER_PROBE:') }
      raise 'wrapper_observer_not_reached:' + name unless marker && r['exit_code'] == 0
      report['observations'][name] = JSON.parse(marker.delete_prefix('B0_WRITER_PROBE:'))
    end
  end
  o = report['observations']
  c = report['checks']
  c['default_wrapper_drops_to_git'] = ['active_default', 'stopped_default'].all? { |name| o[name]['uid'] == account.uid && account.uid != 0 }
  c['supported_option_retains_root'] = ['active_retain_root', 'stopped_retain_root'].all? { |name| o[name]['uid'] == 0 }
  active = o['active_retain_root']
  active_snapshot = active.dig('process_snapshot', 'value')
  c['active_root_observation_complete'] = active_snapshot && active_snapshot['source_complete'] == true
  active_services = active_snapshot && active_snapshot['processes'].select { |row| row['service'] && row['state'] != 'Z' }
  c['active_root_observes_both_fixture_services'] = active_services && active_services.map { |row| row['service'] }.uniq.sort == SERVICES.sort
  c['active_root_supervision_qualified'] = SERVICES.all? do |service|
    status = active.dig('supervision', service, 'value', 'status')
    status && status['qualified'] == true && status['state'] == 'run' && status['pid'] > 0
  end
  c['active_root_barrier_rejected'] = o['active_retain_root']['barrier_passed'] == false
  c['stopped_root_barrier_passed'] = o['stopped_retain_root']['barrier_passed'] == true
  c['stopped_root_supervision_qualified'] = SERVICES.all? do |service|
    status = o['stopped_retain_root'].dig('supervision', service, 'value', 'status')
    status && status['qualified'] == true && status['state'] == 'down' && status['pid'] == 0 &&
      status['state_code'] == 0 && status['desired_not_up'] == true
  end
  c['stopped_default_barrier_rejected'] = o['stopped_default']['barrier_passed'] == false
  snapshot = o['stopped_default'].dig('process_snapshot', 'value')
  c['default_has_observation_permission_errors'] = snapshot && !snapshot['source_complete'] &&
    snapshot['errors'].any? { |row| ['Errno::EACCES', 'Errno::EPERM'].include?(row['class']) }
  c['default_cannot_observe_both_root_fixture_supervisors'] = snapshot && supervisors.all? do |_, pid|
    snapshot['errors'].any? do |row|
      row['pid'] == pid && ['Errno::EACCES', 'Errno::EPERM'].include?(row['class']) && row['message'].include?("/proc/#{pid}/")
    end
  end
  c['fixture_supervisors_are_root'] = report['service_processes'].all? { |row| row['supervisor_uids'].all?(&:zero?) }
  c['packaged_wrapper_unchanged'] = Digest::SHA256.file(WRAPPER).hexdigest == report['wrapper_sha256']
  report['passed'] = c.values.all? { |value| value == true }
rescue StandardError => error
  report['error'] = {'class' => error.class.name, 'message' => error.message, 'backtrace' => error.backtrace}
  report['passed'] = false
ensure
  report['fixture_cleanup'] = supervisors.map do |service, pid|
    cleanup = {'service' => service, 'supervisor_pid' => pid, 'reaped' => false}
    begin
      row = run_record(report, 'exit_fixture_' + service, [SV, '-w', '5', 'exit', '/opt/gitlab/sv/' + service])
      cleanup['exit_command'] = row['exit_code']
      cleanup['reaped'] = wait_until(6) { Process.waitpid(pid, Process::WNOHANG) == pid }
    rescue StandardError => error
      cleanup['error'] = {'class' => error.class.name, 'message' => error.message}
    end
    cleanup
  end
  report['passed'] = false unless report['fixture_cleanup'].all? { |row| row['reaped'] }
  report['completed_at_utc'] = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
  File.write(OUT + '/probe.json', JSON.pretty_generate(report) + "\n")
  puts JSON.generate({'passed' => report['passed'], 'checks' => report['checks'], 'error' => report['error']})
end
exit(report['passed'] ? 0 : 1)
