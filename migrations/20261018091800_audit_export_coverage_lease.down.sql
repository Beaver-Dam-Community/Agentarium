-- outbox_id values and fencing tokens are covered by signed manifests and
-- committed export evidence. Dropping them would make retained manifests
-- unverifiable. Preserve history and use a forward migration instead.
DO $$ BEGIN
  RAISE EXCEPTION 'audit export coverage/lease migration is irreversible; use a forward migration preserving evidence';
END $$;
