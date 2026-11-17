barrier=B0.stopped_services!
rows=cfg.fetch('intents').map { |r| B0.identity(r) }
B0.emit({'kind'=>'identity_authorization','identities'=>rows,'source_complete'=>true,'writer_barrier'=>barrier})
