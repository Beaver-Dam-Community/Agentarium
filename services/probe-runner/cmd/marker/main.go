// Command marker is the fixed binary of the TASK-10 3.2 process probe
// (/probe/bin/marker). The runner execs it once per cycle; the node sensors
// record its process_exec and process_exit in the runner's container. It
// does nothing and exits 0.
package main

func main() {}
