import errno,os
from agentarium_runtime.worker import controls
r=controls()
assert not r.get('error'),r
try:
    os.execve('/bin/true',['/bin/true'],{})
except OSError as e:
    assert e.errno==errno.EPERM,e
else:
    raise AssertionError('execve returned unexpectedly')
print('PASS: native worker filter rejects execve with EPERM')
