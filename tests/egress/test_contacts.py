"""Offline contact-service authentication and Pod configuration checks."""
import json
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
class Contacts(unittest.TestCase):
    def test_proxy_identity_and_service_boundary(self):
        items = json.loads((ROOT/'deploy/gcp/base/contact-services/contacts.yaml').read_text())['items']
        service_accounts = [o for o in items if o['kind']=='ServiceAccount']
        self.assertEqual(len(service_accounts), 3)
        for sa in service_accounts:
            self.assertFalse(sa['automountServiceAccountToken'])
            self.assertNotIn('iam.gke.io/gcp-service-account', sa['metadata'].get('annotations', {}))
        deployments = [o for o in items if o['kind']=='Deployment']
        self.assertEqual(len(deployments), 3)
        for deploy in deployments:
            pod = deploy['spec']['template']['spec']
            self.assertEqual(pod['serviceAccountName'], deploy['metadata']['name'])
            self.assertFalse(pod['automountServiceAccountToken'])
            self.assertEqual(pod['nodeSelector']['node-restriction.kubernetes.io/agentarium-role'], 'control')
            self.assertIn(deploy['metadata']['namespace'], {'agent-control', 'agent-observe'})
            self.assertEqual(pod['tolerations'], [{
                'key': 'agentarium.io/observe-not-ready', 'operator': 'Equal',
                'value': 'true', 'effect': 'NoSchedule',
            }], 'bootstrap services must start while observation readiness is pending')
            proxy = pod['initContainers'][0]
            self.assertEqual(proxy['restartPolicy'], 'Always')
            self.assertIn('--address=127.0.0.1', proxy['args'])
            self.assertIn('--auto-iam-authn', proxy['args'])
            self.assertEqual(sum(arg.startswith('--impersonate-service-account=') for arg in proxy['args']), 1)
            self.assertFalse(any('impersonate' in arg for arg in pod['containers'][0]['args']))
            self.assertTrue(pod['securityContext']['runAsNonRoot'])
            for container in pod['containers'] + pod['initContainers']:
                self.assertTrue(container['securityContext']['readOnlyRootFilesystem'])
                self.assertFalse(container['securityContext']['allowPrivilegeEscalation'])
            template_args = [arg for arg in pod['containers'][0]['args'] if 'certificate-template=' in arg]
            self.assertEqual(template_args, [
                '--service-certificate-template=${SERVICE_CERTIFICATE_TEMPLATE}',
                '--client-certificate-template=${CLIENT_CERTIFICATE_TEMPLATE}',
            ] if deploy['metadata']['name'] == 'workload-identity' else [])
            if deploy['metadata']['name'] != 'workload-identity':
                tokens = [source['serviceAccountToken'] for vol in pod['volumes']
                          for source in vol.get('projected', {}).get('sources', []) if 'serviceAccountToken' in source]
                expected = [{'path':'token','expirationSeconds':600,'audience':'agentarium-identity'}]
                if deploy['metadata']['name'] == 'control-health':
                    # NodeFacts Node get/list (TASK-06 3.2, #199): default-audience API token.
                    expected.append({'path':'token','expirationSeconds':600})
                self.assertEqual(tokens, expected)
            if deploy['metadata']['name']=='control-health':
                volumes = {v['name']: v for v in pod['volumes']}
                self.assertEqual(volumes['startup-capture']['configMap'],
                                 {'name':'control-health-startup-capture','optional':True})
                self.assertIn('--startup-capture=/etc/agentarium/startup-capture/startup_capture.json', pod['containers'][0]['args'])
                mounts = {m['name']: m for m in pod['containers'][0]['volumeMounts']}
                self.assertEqual(mounts['api-token']['mountPath'], '/var/run/secrets/kubernetes.io/serviceaccount')
                self.assertTrue(mounts['api-token']['readOnly'] and mounts['startup-capture']['readOnly'])
                self.assertEqual(deploy['spec']['strategy']['type'], 'Recreate')
                self.assertIn('--epoch-dir=/var/lib/agentarium/epoch',pod['containers'][0]['args'])
    def test_identity_claim_key_csi(self):
        items = json.loads((ROOT/'deploy/gcp/base/contact-services/contacts.yaml').read_text())['items']
        spc, = [o for o in items if o['kind'] == 'SecretProviderClass']
        self.assertEqual(spc['apiVersion'], 'secrets-store.csi.x-k8s.io/v1')
        self.assertEqual(spc['metadata'], {'name': 'workload-identity-claim-key', 'namespace': 'agent-control'})
        self.assertEqual(spc['spec']['provider'], 'gke')
        self.assertEqual(spc['spec']['parameters'], {'secrets':
            '- resourceName: "${CLAIM_KEY_SECRET}/versions/${CLAIM_KEY_SECRET_VERSION}"\n  path: "claim-key"\n'})
        self.assertNotIn('latest', json.dumps(spc))
        for deploy in [o for o in items if o['kind'] == 'Deployment']:
            pod = deploy['spec']['template']['spec']
            csi = [v for v in pod['volumes'] if 'csi' in v]
            if deploy['metadata']['name'] != 'workload-identity':
                self.assertEqual(csi, [], 'only identity receives the claim key')
                continue
            self.assertEqual(csi, [{'name': 'claim-key', 'csi': {'driver': 'secrets-store-gke.csi.k8s.io', 'readOnly': True,
                                    'volumeAttributes': {'secretProviderClass': 'workload-identity-claim-key'}}}])
            self.assertEqual(pod['nodeSelector']['iam.gke.io/gke-metadata-server-enabled'], 'true')
            app = pod['containers'][0]
            self.assertIn('--claim-key-file=/var/run/secrets/agentarium/claim-key', app['args'])
            self.assertIn({'name': 'claim-key', 'mountPath': '/var/run/secrets/agentarium', 'readOnly': True}, app['volumeMounts'])
            proxy = pod['initContainers'][0]
            self.assertFalse(any(m['name'] == 'claim-key' for m in proxy.get('volumeMounts', [])))
            self.assertFalse(any('secretKeyRef' in json.dumps(e) for e in app['env']))
        main = (ROOT/'services/identity/cmd/identity/main.go').read_text()
        self.assertIn('"claim-key-file", "/var/run/secrets/agentarium/claim-key"', main)

    def test_identity_rbac_is_scoped(self):
        items=json.loads((ROOT/'deploy/gcp/base/rbac/workload-identity.yaml').read_text())['items']
        roles=[o for o in items if o['kind']=='Role']
        self.assertEqual(len(roles),7)
        contacts=json.loads((ROOT/'deploy/gcp/base/contact-services/contacts.yaml').read_text())['items']
        identity=next(o for o in contacts if o['kind']=='Deployment' and o['metadata']['name']=='workload-identity')
        args=identity['spec']['template']['spec']['containers'][0]['args']
        namespaces=[arg.split('=',1)[1] for arg in args if arg.startswith('--pod-namespaces=')]
        self.assertEqual(len(namespaces),1)
        configured=namespaces[0].split(',')
        self.assertEqual(len(configured),len(set(configured)))
        self.assertEqual(set(configured),{role['metadata']['namespace'] for role in roles})
        for role in roles:
            self.assertEqual(role['rules'],[{'apiGroups':[''],'resources':['pods'],'verbs':['get','list','watch']}])
        for obj in items:
            for rule in obj.get('rules',[]):
                self.assertNotIn('*',rule['resources']);self.assertNotIn('*',rule['verbs'])
                self.assertNotIn('secrets',rule['resources']);self.assertNotIn('pods/exec',rule['resources'])
