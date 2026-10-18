-- name: Connects :many
SELECT source_event_id,boot_id,coalesce(container_id,'')::text AS container_id,coalesce(process_exec_id,'')::text AS process_exec_id,
 coalesce(pod_uid::text,'')::text AS pod_uid,coalesce(netns_inode,0)::bigint AS netns_inode,coalesce(sock_ptr,'')::text AS sock_ptr,
 host(saddr)::text AS saddr,sport,host(daddr)::text AS daddr,dport,source_time
FROM audit.kernel_events
WHERE event_type='tcp_connect' AND node_uid=sqlc.arg(node_uid)::uuid
AND source_time>=sqlc.arg(from_time)::timestamptz AND source_time<sqlc.arg(to_time)::timestamptz
AND saddr IS NOT NULL AND sport IS NOT NULL AND daddr IS NOT NULL AND dport IS NOT NULL
ORDER BY source_event_id;

-- name: States :many
-- tcp_new_state 1 = TCP_ESTABLISHED, 7 = TCP_CLOSE (COMMON KernelEvent).
SELECT source_event_id,boot_id,coalesce(sock_ptr,'')::text AS sock_ptr,host(saddr)::text AS saddr,sport,host(daddr)::text AS daddr,dport,
 source_time,tcp_new_state
FROM audit.kernel_events
WHERE event_type='tcp_state' AND node_uid=sqlc.arg(node_uid)::uuid
AND source_time>=sqlc.arg(from_time)::timestamptz AND source_time<sqlc.arg(to_time)::timestamptz
AND saddr IS NOT NULL AND sport IS NOT NULL AND daddr IS NOT NULL AND dport IS NOT NULL AND sock_ptr IS NOT NULL
ORDER BY source_event_id;

-- name: Intervals :many
-- Only the latest mapping_version of each interval identity: the lifecycle
-- store appends revisions and keeps old ones.
SELECT DISTINCT ON (cluster_uid,pod_uid,node_uid,boot_id,container_id,restart_instance) *
FROM correlation.lifecycle_intervals
WHERE node_uid=sqlc.arg(node_uid)::uuid
ORDER BY cluster_uid,pod_uid,node_uid,boot_id,container_id,restart_instance,mapping_version DESC;

-- name: Observations :many
SELECT o.attempt_id,a.action_id,o.pod_uid,o.netns_inode,host(o.local_addr)::text AS local_addr,o.local_port,
 host(o.peer_addr)::text AS peer_addr,o.peer_port,o.connect_started_at,o.send_started_at
FROM coordinator.attempt_observations o JOIN coordinator.attempts a ON a.attempt_id=o.attempt_id
WHERE a.adapter_node_uid=sqlc.arg(node_uid)::uuid AND o.pod_uid IS NOT NULL AND o.netns_inode IS NOT NULL AND o.local_addr IS NOT NULL AND o.local_port IS NOT NULL
AND o.peer_addr IS NOT NULL AND o.peer_port IS NOT NULL AND o.connect_started_at IS NOT NULL AND o.send_started_at IS NOT NULL
AND o.connect_started_at<=sqlc.arg(to_time)::timestamptz AND o.send_started_at>=sqlc.arg(from_time)::timestamptz
ORDER BY o.attempt_id;

-- name: Rules :many
SELECT algorithm_version,host(service_vip)::text AS service_vip,service_port,endpoint_cidr::text AS endpoint_cidr,endpoint_port,kernel_side,adapter_side,measured_run_id
FROM correlation.tuple_normalization_rules WHERE algorithm_version=sqlc.arg(algorithm_version)::text
ORDER BY service_vip,service_port,endpoint_cidr;
