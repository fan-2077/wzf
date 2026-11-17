require 'json'
require 'digest'
require 'base64'
report={'schema'=>'b0-readonly-clock-probe-v1','read_errors'=>[]}
values={}
[['boot_id','/proc/sys/kernel/random/boot_id',false],
 ['time_namespace','/proc/self/ns/time',true],
 ['time_namespace_for_children','/proc/self/ns/time_for_children',true],
 ['timens_offsets','/proc/self/timens_offsets',false]].each do |name,path,link|
  begin
    raw=link ? File.readlink(path) : File.binread(path)
    values[name]=raw
    report[link ? name : name+'_base64']=link ? raw : Base64.strict_encode64(raw)
  rescue StandardError=>error
    report['read_errors'] << {'name'=>name,'path'=>path,'class'=>error.class.name,'message'=>error.message}
  end
end
valid=report['read_errors'].empty? && values.length==4 &&
 values['boot_id'].strip.match?(/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/) &&
 values['time_namespace'].match?(/\Atime:\[[0-9]+\]\z/) &&
 values['time_namespace']==values['time_namespace_for_children'] && !values['timens_offsets'].empty?
report['valid_identity_inputs']=valid
if valid
  report['identity']={'schema'=>'b0-monotonic-clock-identity-v1','boot_id'=>values['boot_id'].strip,
   'time_namespace'=>values['time_namespace'],'timens_offsets_sha256'=>Digest::SHA256.hexdigest(values['timens_offsets'])}
end
report['monotonic']=Process.clock_gettime(Process::CLOCK_MONOTONIC)
puts JSON.generate(report)
