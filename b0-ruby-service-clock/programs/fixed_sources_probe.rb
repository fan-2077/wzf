require 'json'
require 'digest'
require 'base64'
SOURCES=JSON.parse("[{\"expected_sha256\":null,\"name\":\"version_manifest\",\"path_or_pattern\":\"/opt/gitlab/version-manifest.json\",\"unique_glob\":false},{\"expected_sha256\":\"67fe92f3596fbe0cbfd9b82a4150ac1443bc885316087aa87388097e43f09697\",\"name\":\"sidekiq_cluster_cli\",\"path_or_pattern\":\"/opt/gitlab/embedded/service/gitlab-rails/sidekiq_cluster/cli.rb\",\"unique_glob\":false},{\"expected_sha256\":\"14236db6614fe36b179f5eac86b57457feca9e1e2344316763d23de52bb3e9a2\",\"name\":\"sidekiq_cluster\",\"path_or_pattern\":\"/opt/gitlab/embedded/service/gitlab-rails/sidekiq_cluster/sidekiq_cluster.rb\",\"unique_glob\":false},{\"expected_sha256\":\"12f2ca711d6093446f34712a15a278428bd70f4eb2dc299092745a3eb9bd7d40\",\"name\":\"process_supervisor\",\"path_or_pattern\":\"/opt/gitlab/embedded/service/gitlab-rails/lib/gitlab/process_supervisor.rb\",\"unique_glob\":false},{\"expected_sha256\":\"9e0c860e6b95578ae087c13fe38ef3243472fbb8b74075261a47d8131bd0785e\",\"name\":\"process_management\",\"path_or_pattern\":\"/opt/gitlab/embedded/service/gitlab-rails/lib/gitlab/process_management.rb\",\"unique_glob\":false},{\"expected_sha256\":\"024e8c21b4e4201794cc040244ced2295da22e7152caa2ab66b3b6d9d1284eeb\",\"name\":\"metrics_server\",\"path_or_pattern\":\"/opt/gitlab/embedded/service/gitlab-rails/metrics_server/metrics_server.rb\",\"unique_glob\":false},{\"expected_sha256\":\"e4beaf3fc6894583ead8bd4e42dde1cec525037c872511b76dad76e933e4076d\",\"name\":\"puma_cluster\",\"path_or_pattern\":\"/opt/gitlab/embedded/lib/ruby/gems/*/gems/puma-7.2.0/lib/puma/cluster.rb\",\"unique_glob\":true},{\"expected_sha256\":\"50d421e29a29c0671217772556cc542b91b95f0dfe365015e05ce008b96e2bfc\",\"name\":\"omnibus_ctl\",\"path_or_pattern\":\"/opt/gitlab/embedded/lib/ruby/gems/*/gems/omnibus-ctl-0.6.12/lib/omnibus-ctl.rb\",\"unique_glob\":true},{\"expected_sha256\":\"a414f5b6c2709e0ca8ee4faffb9117de41ed9d35aa4967873f04c2382475c235\",\"name\":\"puma_run_template\",\"path_or_pattern\":\"/opt/gitlab/embedded/cookbooks/gitlab/templates/default/sv-puma-run.erb\",\"unique_glob\":false},{\"expected_sha256\":\"861fc54c66d6333a1f69693868d5e0dcaf65d5588a66cf73f6c956b8ffb070d4\",\"name\":\"sidekiq_run_template\",\"path_or_pattern\":\"/opt/gitlab/embedded/cookbooks/gitlab/templates/default/sv-sidekiq-run.erb\",\"unique_glob\":false},{\"expected_sha256\":null,\"name\":\"sv\",\"path_or_pattern\":\"/opt/gitlab/embedded/bin/sv\",\"unique_glob\":false},{\"expected_sha256\":null,\"name\":\"runsv\",\"path_or_pattern\":\"/opt/gitlab/embedded/bin/runsv\",\"unique_glob\":false},{\"expected_sha256\":null,\"name\":\"chpst\",\"path_or_pattern\":\"/opt/gitlab/embedded/bin/chpst\",\"unique_glob\":false}]")
rows=SOURCES.map do |entry|
  row=entry.dup
  begin
    paths=entry['unique_glob'] ? Dir.glob(entry['path_or_pattern']).sort : [entry['path_or_pattern']]
    row['resolved_paths']=paths
    raise 'fixed_source_not_unique' unless paths.length==1
    path=paths.first
    before=File.stat(path)
    raise 'fixed_source_not_regular' unless before.file?
    raise 'fixed_source_over_bound' if before.size>8*1024*1024
    raw=File.binread(path)
    after=File.stat(path)
    raise 'fixed_source_changed_during_read' unless [before.dev,before.ino,before.size,before.mtime.to_f]==[after.dev,after.ino,after.size,after.mtime.to_f] && raw.bytesize==after.size
    row.merge!({'path'=>path,'realpath'=>File.realpath(path),'device'=>after.dev,'inode'=>after.ino,
      'bytes'=>raw.bytesize,'sha256'=>Digest::SHA256.hexdigest(raw),'data_base64'=>Base64.strict_encode64(raw),
      'complete'=>true})
  rescue StandardError=>error
    row.merge!({'complete'=>false,'error_class'=>error.class.name,'error'=>error.message})
  end
  row
end
generated=['/opt/gitlab/service/puma/run','/opt/gitlab/service/sidekiq/run',
 '/opt/gitlab/service/puma/control/t','/opt/gitlab/init/puma','/opt/gitlab/init/sidekiq'].map do |path|
  {'path'=>path,'exists'=>File.exist?(path),'symlink'=>File.symlink?(path),
   'link_target'=>File.symlink?(path) ? File.readlink(path) : nil,
   'scope'=>'generated configured-runtime path; absence in unstarted image is expected and not a source failure'}
end
puts JSON.generate({'schema'=>'b0-fixed-image-sources-probe-v1','sources'=>rows,
 'all_fixed_sources_complete'=>rows.all? { |row|row['complete'] },'generated_runtime_paths'=>generated,
 'service_started'=>false,'business_actions'=>0})
