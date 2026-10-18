# probe-sink (TASK-10 3.2 tcp probe target)

`agent-targets/probe-sink` listens on TCP 8443, accepts connections from the
probe runners (TASK-06 allow table), waits up to 5 s for the peer to close and
closes. No data and no credential. Image:
`docker build -f build/docker/go-service.Dockerfile --build-arg CMD=./services/probe-sink/cmd/probe-sink -t <repo>/probe-sink .`
(entrypoint `/app`).
