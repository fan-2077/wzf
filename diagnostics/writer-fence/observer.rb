# Runs before application boot, through the unmodified packaged wrapper.
require 'json'
require 'digest'
ENV['B0_ARGUMENTS'] = '{}'
load '/programs/ruby_common.rb'
load '/programs/service_supervision.rb'

def capture
  {'value' => yield}
rescue StandardError => error
  {'error' => {'class' => error.class.name, 'message' => error.message}}
end

started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
supervision = ['puma', 'sidekiq'].to_h do |service|
  [service, capture { B0.supervision_snapshot(service) }]
end
snapshot = capture { B0.process_snapshot }
barrier = capture { B0.stopped_services! }
observed = {
  'schema' => 'b0-writer-observer-diagnostic-v1',
  'probe_name' => ENV.fetch('B0_PROBE_NAME'),
  'uid' => Process.uid, 'euid' => Process.euid,
  'gid' => Process.gid, 'egid' => Process.egid, 'groups' => Process.groups,
  'pid' => Process.pid, 'ppid' => Process.ppid,
  'started_monotonic' => started,
  'completed_monotonic' => Process.clock_gettime(Process::CLOCK_MONOTONIC),
  'clock_identity' => capture { B0.clock_identity },
  'supervision' => supervision, 'process_snapshot' => snapshot,
  'actual_stopped_services_call' => barrier,
  'barrier_passed' => barrier.key?('value'),
  'scope' => 'packaged-wrapper and unchanged B0 observer; controlled Bundler boot hook; no Rails application boot'
}
puts 'B0_WRITER_PROBE:' + JSON.generate(observed)
