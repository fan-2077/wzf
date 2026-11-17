require 'zlib'
require 'stringio'
ids=cfg.fetch('job_ids')
raise 'invalid_job_ids' unless ids.is_a?(Array) && ids.all? { |x|x.is_a?(String) && x.match?(/\A[A-Za-z0-9_-]{1,128}\z/) }
files=[];matched=[];unparsed=[];total=0
log_names = lambda do
  Dir.children('/var/log/gitlab/sidekiq').select { |name| name=='current' || name.match?(/\A(?:sidekiq\.log(?:\.[0-9]+)?(?:\.gz)?|@[a-fA-F0-9]+\.[su])\z/) }.sort
end
names_before=log_names.call
names_before.each do |name|
  path='/var/log/gitlab/sidekiq/'+name
  next unless File.file?(path)
  raise 'log_symlink' if File.symlink?(path)
  stat=File.stat(path)
  raise 'log_file_over_limit' if stat.size>33554432
  blob=File.binread(path)
  total+=blob.bytesize
  raise 'logs_total_over_limit' if total>134217728
  raw=name.end_with?('.gz') ? Zlib::GzipReader.wrap(StringIO.new(blob), &:read) : blob
  raise 'log_expanded_over_limit' if raw.bytesize>67108864
  count=0
  raw.each_line do |line|
    count+=1
    selected=ids.any? { |id| line.include?(id) }
    lifecycle=line.match?(/(?:Starting processing|Booting Sidekiq|Sidekiq.*version|Pausing to allow|Terminating busy|hard.shutdown|All threads stopped|Bye!|Shutting down|Stopping quiet|job_status)/)
    next unless selected || lifecycle
    pos=line.index('{')
    begin
      row=pos ? JSON.parse(line[pos..]) : nil
    rescue JSON::ParserError
      row=nil
    end
    item={'file'=>name,'line'=>count,'line_sha256'=>B0.sha(line),'selected_job'=>selected,'lifecycle'=>lifecycle,'row'=>row}
    if row
      # Fields are public application job/lifecycle logs. No credentials are read.
      matched << item
    else
      item['raw_base64']=Base64.strict_encode64(line)
      unparsed << item
    end
  end
  after=File.stat(path)
  files << {'name'=>name,'inode'=>stat.ino,'bytes'=>stat.size,'mtime_ns'=>stat.mtime.nsec,
            'sha256'=>B0.sha(blob),'capture_encoding'=>'zlib+base64',
            'capture_zlib_base64'=>Base64.strict_encode64(Zlib::Deflate.deflate(blob)),
            'lines'=>count,'unchanged_during_read'=>after.ino==stat.ino && after.size==stat.size && after.mtime==stat.mtime}
end
names_after=log_names.call
B0.emit({'kind'=>'history_logs','names_before'=>names_before,'names_after'=>names_after,'files'=>files,'matching_records'=>matched,'unparsed_selected'=>unparsed,
         'source_complete'=>!files.empty? && names_before==names_after && files.map { |f|f['name'] }==names_before && files.all? { |f|f['unchanged_during_read'] },'requested_job_ids'=>ids,
         'total_bytes'=>total,'historical_terminal_claimed'=>false})
