import json

import httpx
import pytest
from google.api_core import exceptions

from agentarium_discovery.clients import KubernetesJobs
from agentarium_discovery.snapshots import (
    GCSBackend,
    LocalBackend,
    ObjectMissing,
    ReadRejected,
    SnapshotNotFound,
    SnapshotStore,
    backend_for,
)
from conftest import SNAPSHOT_ID, write_snapshot


class FakeBlob:
    def __init__(self, objects, key, reads):
        self.objects, self.key, self.reads = objects, key, reads

    def download_as_bytes(self):
        self.reads.append(self.key)
        if self.key not in self.objects:
            raise exceptions.NotFound(self.key)
        return self.objects[self.key]


class FakeBucket:
    def __init__(self, objects, reads):
        self.objects, self.reads = objects, reads

    def blob(self, key):
        return FakeBlob(self.objects, key, self.reads)


class FakeClient:
    """In-memory stand-in for google.cloud.storage.Client (no GCP calls)."""

    def __init__(self, objects):
        self.objects, self.reads, self.buckets = objects, [], []

    def bucket(self, name):
        self.buckets.append(name)
        return FakeBucket(self.objects, self.reads)


def gcs_objects(tmp_path):
    write_snapshot(tmp_path)
    root = tmp_path / "snapshots"
    return {str(p.relative_to(tmp_path)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_gcs_backend_reads_the_same_snapshot_as_local(tmp_path):
    client = FakeClient(gcs_objects(tmp_path))
    gcs = SnapshotStore(GCSBackend("karrot-rina-agentarium-discovery", client))
    local = SnapshotStore(tmp_path)
    assert client.buckets == ["karrot-rina-agentarium-discovery"]
    assert gcs.load(SNAPSHOT_ID) == local.load(SNAPSHOT_ID)
    args = (SNAPSHOT_ID, "httpx/_client.py", 1, 3)
    assert gcs.read_source(*args) == local.read_source(*args)
    assert client.reads[-1] == f"snapshots/{SNAPSHOT_ID}/src/httpx/_client.py"
    assert gcs.read_callgraph(SNAPSHOT_ID, "httpx.Client.send", 3) == local.read_callgraph(SNAPSHOT_ID, "httpx.Client.send", 3)


def test_gcs_backend_keeps_the_response_limit(tmp_path):
    gcs = SnapshotStore(GCSBackend("bucket-1", FakeClient(gcs_objects(tmp_path))))
    body = gcs.read_source(SNAPSHOT_ID, "httpx/big.py", 1, 300)
    assert body["truncated"] is True
    assert len(json.dumps(body, separators=(",", ":")).encode()) <= 64 * 1024


def test_gcs_missing_snapshot_and_unlisted_path(tmp_path):
    client = FakeClient(gcs_objects(tmp_path))
    gcs = SnapshotStore(GCSBackend("bucket-1", client))
    assert not gcs.exists("d" * 64)
    with pytest.raises(SnapshotNotFound):
        gcs.load("d" * 64)
    # Only manifest paths are fetched; nothing else in the bucket is reachable.
    with pytest.raises(ReadRejected):
        gcs.read_source(SNAPSHOT_ID, "httpx/not_listed.py", 1, 1)
    assert not any(k.endswith("not_listed.py") for k in client.reads)
    with pytest.raises(ReadRejected):
        gcs.read_source(SNAPSHOT_ID, "../manifest.json", 1, 1)


def test_incomplete_snapshot_without_manifest_is_not_found(tmp_path):
    objects = gcs_objects(tmp_path)
    del objects[f"snapshots/{SNAPSHOT_ID}/manifest.json"]
    assert not SnapshotStore(GCSBackend("bucket-1", FakeClient(objects))).exists(SNAPSHOT_ID)


def test_loaded_documents_are_cached_per_snapshot(tmp_path):
    client = FakeClient(gcs_objects(tmp_path))
    gcs = SnapshotStore(GCSBackend("bucket-1", client))
    gcs.load(SNAPSHOT_ID)
    n = len(client.reads)
    gcs.load(SNAPSHOT_ID)
    gcs.read_callgraph(SNAPSHOT_ID, "httpx.Client.send", 1)
    assert len(client.reads) == n


def test_snapshot_id_must_be_a_digest(tmp_path):
    client = FakeClient(gcs_objects(tmp_path))
    gcs = SnapshotStore(GCSBackend("bucket-1", client))
    for bad in ["../x", "A" * 64, "a" * 63, "a/b"]:
        assert not gcs.exists(bad)
    assert client.reads == []


def test_local_backend_does_not_follow_symlinks_out_of_root(tmp_path):
    root = tmp_path / "root"
    write_snapshot(root)
    secret = tmp_path / "secret.txt"
    secret.write_text("secret")
    (root / "snapshots" / SNAPSHOT_ID / "src" / "httpx" / "_client.py").unlink()
    (root / "snapshots" / SNAPSHOT_ID / "src" / "httpx" / "_client.py").symlink_to(secret)
    with pytest.raises(SnapshotNotFound):
        SnapshotStore(root).read_source(SNAPSHOT_ID, "httpx/_client.py", 1, 1)
    with pytest.raises(ObjectMissing):
        LocalBackend(root).read("snapshots/missing")


def test_backend_for_selects_by_root(tmp_path, monkeypatch):
    assert isinstance(backend_for(tmp_path), LocalBackend)
    made = []
    monkeypatch.setattr("agentarium_discovery.snapshots.GCSBackend",
                        lambda bucket: made.append(bucket) or "gcs")
    assert backend_for("gs://karrot-rina-agentarium-discovery/") == "gcs"
    assert made == ["karrot-rina-agentarium-discovery"]
    with pytest.raises(ValueError):
        backend_for("gs://bucket-1/snapshots")


def test_gcs_backend_rejects_invalid_bucket_names():
    for bad in ["", "A-bucket", "b", "bucket/x"]:
        with pytest.raises(ValueError):
            GCSBackend(bad, FakeClient({}))


IMAGE = "asia-northeast3-docker.pkg.dev/p/agentarium/discovery-snapshot@sha256:" + "0" * 64


def launched_job(tmp_path, monkeypatch, **kw):
    sent = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent["job"] = json.loads(request.content)
        return httpx.Response(201, json={})

    jobs = KubernetesJobs("agent-observe", IMAGE, "karrot-rina-agentarium-discovery",
                          client=httpx.Client(transport=httpx.MockTransport(handler)), **kw)
    token = tmp_path / "token"
    token.write_text("t")
    monkeypatch.setattr(KubernetesJobs, "TOKEN", str(token))
    uri = "gs://karrot-rina-agentarium-discovery/sources/" + "0" * 64 + ".tar.gz"
    jobs.launch("r" * 32, "python", uri, "0" * 64, "httpx", "0.27.0")
    return sent["job"]


def test_snapshot_job_writes_gs_root_without_fuse(tmp_path, monkeypatch):
    tmpl = launched_job(tmp_path, monkeypatch)["spec"]["template"]
    c = tmpl["spec"]["containers"][0]
    args = c["args"]
    assert args[args.index("--out-root") + 1] == "gs://karrot-rina-agentarium-discovery"
    assert args[args.index("--work-dir") + 1] == "/work"
    assert "annotations" not in tmpl["metadata"]
    assert all("csi" not in v for v in tmpl["spec"]["volumes"])


def test_snapshot_job_passes_role_admission_and_restricted_pss(tmp_path, monkeypatch):
    job = launched_job(tmp_path, monkeypatch)
    tmpl = job["spec"]["template"]
    spec = tmpl["spec"]
    c = spec["containers"][0]
    # Own KSA, label == KSA (agent-role-contract ROLE_LABEL_OR_PRIORITY_INVALID).
    assert spec["serviceAccountName"] == "discovery-snapshot"
    assert tmpl["metadata"]["labels"]["app.kubernetes.io/name"] == "discovery-snapshot"
    assert spec["automountServiceAccountToken"] is False
    # Placement (ROLE_PLACEMENT_INVALID) and digest image (ROLE_IMAGE_NOT_ALLOWED).
    assert spec["nodeSelector"] == {"node-restriction.kubernetes.io/agentarium-role": "control"}
    assert spec["schedulerName"] == "default-scheduler" and "nodeName" not in spec
    assert c["image"] == IMAGE and "@sha256:" in c["image"]
    # PSS restricted.
    assert spec["securityContext"] == {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                       "seccompProfile": {"type": "RuntimeDefault"}}
    assert c["securityContext"] == {"readOnlyRootFilesystem": True, "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]}}
    assert "hostNetwork" not in spec and "runtimeClassName" not in spec and "priorityClassName" not in spec
    # Writable scratch only on the size-limited emptyDir (TASK-02 3.4 archive limits, PR #22).
    assert spec["volumes"] == [{"name": "work", "emptyDir": {"sizeLimit": "2Gi"}}]
    assert c["volumeMounts"] == [{"name": "work", "mountPath": "/work"}]
    assert c["resources"] == {"requests": {"cpu": "250m", "memory": "512Mi", "ephemeral-storage": "256Mi"},
                              "limits": {"cpu": "2", "memory": "2Gi", "ephemeral-storage": "2560Mi"}}
    assert job["spec"]["activeDeadlineSeconds"] == 3600 and job["spec"]["backoffLimit"] == 0


def test_snapshot_job_service_account_override(tmp_path, monkeypatch):
    spec = launched_job(tmp_path, monkeypatch, service_account="other-ksa")["spec"]["template"]
    assert spec["spec"]["serviceAccountName"] == "other-ksa"
    assert spec["metadata"]["labels"]["app.kubernetes.io/name"] == "other-ksa"


@pytest.mark.parametrize("image", [
    "asia-northeast3-docker.pkg.dev/p/agentarium/discovery-snapshot:latest",
    "asia-northeast3-docker.pkg.dev/p/agentarium/discovery-snapshot",
    "asia-northeast3-docker.pkg.dev/p/agentarium/discovery-snapshot@sha256:" + "0" * 63,
    "repo@sha256:" + "G" * 64,
    "",
])
def test_snapshot_job_image_must_be_a_digest(image):
    with pytest.raises(ValueError):
        KubernetesJobs("agent-observe", image, "bucket-1", client=httpx.Client())
