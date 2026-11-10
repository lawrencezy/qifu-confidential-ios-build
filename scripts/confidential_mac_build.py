"""Confidential one-job iOS builder. Public code; private inputs/results use AES-GCM.
No application source, signing key, user password or build log is printed.
Only manual workflow execution is supported. Never uploads to App Store Connect.
"""
from __future__ import annotations
import base64, hashlib, io, json, os, plistlib, re, shutil, subprocess, sys, time, urllib.request, zipfile
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, pkcs12

INPUT_AAD = b'QIFU_CONFIDENTIAL_IOS_INPUT_V1'
ROOT = Path(os.environ.get('RUNNER_TEMP', '.')) / 'confidential-ios'
REPO = os.environ.get('GITHUB_REPOSITORY', '')
RUN_ID = os.environ.get('GITHUB_RUN_ID', '')

def key():
    value = base64.b64decode(os.environ['CONFIDENTIAL_IOS_KEY'], validate=True)
    if len(value) != 32: raise ValueError('Wrong encryption key length')
    return value

def decrypt_packet(path):
    blob = Path(path).read_bytes()
    if blob[:8] != b'QIFUIN01': raise ValueError('Wrong confidential input format')
    return json.loads(AESGCM(key()).decrypt(blob[8:20], blob[20:], INPUT_AAD))

def private_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)

def extract_source(raw, destination):
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        for entry in z.infolist():
            p = Path(entry.filename)
            if p.is_absolute() or '..' in p.parts or '\\' in entry.filename:
                raise ValueError('Unsafe source archive entry')
            if not entry.filename.startswith('ios/') or entry.is_dir(): continue
            private_write(destination / p, z.read(entry))

def run_private(args, name, cwd=None, timeout=900, input=None):
    with (ROOT / (name + '.log')).open('ab') as log:
        proc = subprocess.run(args, cwd=cwd, input=input, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    if proc.returncode: raise RuntimeError(name + ' failed; details available only in encrypted result')

def cms(path):
    raw = subprocess.check_output(['/usr/bin/security', 'cms', '-D', '-i', str(path)], stderr=subprocess.DEVNULL)
    return plistlib.loads(raw)

def verify_ipa(ipa, cfg):
    target = ROOT / 'verify'
    with zipfile.ZipFile(ipa) as z: z.extractall(target)
    apps = list((target / 'Payload').glob('*.app'))
    if len(apps) != 1: raise ValueError('IPA must contain exactly one application')
    main = apps[0]; extensions = list((main / 'PlugIns').glob('*.appex'))
    if len(extensions) != 1: raise ValueError('Original share extension missing')
    results = []
    for i, bundle in enumerate([main] + extensions):
        run_private(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(bundle)], 'signature_check_' + str(i))
        info = plistlib.loads((bundle / 'Info.plist').read_bytes())
        profile = cms(bundle / 'embedded.mobileprovision')
        entraw = subprocess.check_output(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(bundle)], stderr=subprocess.DEVNULL)
        ent = plistlib.loads(entraw)
        pe = profile['Entitlements']; bid = info['CFBundleIdentifier']
        expected = cfg['bundle_id'] + ('.share' if i else '')
        if bid != expected: raise ValueError('Actual bundle identity mismatch')
        if profile['TeamIdentifier'] != [cfg['team_id']]: raise ValueError('Wrong profile team')
        if pe['application-identifier'] != cfg['team_id'] + '.' + expected: raise ValueError('Wrong profile application identity')
        if ent.get('com.apple.developer.team-identifier') != cfg['team_id']: raise ValueError('Wrong signed team')
        if cfg['app_group'] not in pe.get('com.apple.security.application-groups', []): raise ValueError('Profile does not authorize shared container')
        if cfg['app_group'] not in ent.get('com.apple.security.application-groups', []): raise ValueError('Application did not retain shared container')
        if pe.get('get-task-allow', False): raise ValueError('Unexpected development/debug signing')
        if base64.b64decode(cfg['certificate_der']) not in profile['DeveloperCertificates']: raise ValueError('Provided certificate not in profile')
        expiry = profile['ExpirationDate'].replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc): raise ValueError('Expired profile')
        devices = profile.get('ProvisionedDevices', [])
        if cfg['export_method'] == 'release-testing' and not devices: raise ValueError('No registered-device installation entitlement')
        results.append({'bundle_id': bid, 'profile_device_count': len(devices), 'shared_container_authorized': True, 'signature_verified': True, 'profile_expires_utc': expiry.isoformat()})
    return results

def build():
    if sys.platform != 'darwin': raise RuntimeError('Build only executes on a real macOS runner')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=False)
    packet = decrypt_packet(Path(os.environ['GITHUB_WORKSPACE']) / 'inputs/current.bin')
    cfg = packet['configuration']
    report = {'started_utc': datetime.now(timezone.utc).isoformat(), 'success': False, 'app_store_upload': False, 'export_method': cfg['export_method'], 'stages': []}
    keychain = ROOT / 'build.keychain-db'
    pemkey = ROOT / 'import-key.pem'; pemcert = ROOT / 'import-cert.pem'
    try:
        source = ROOT / 'source'; extract_source(base64.b64decode(packet['source_zip']), source)
        ios = source / 'ios'; spec_path = ios / 'project.yml'
        text = spec_path.read_text(encoding='utf-8')
        old_group = plistlib.loads((ios / 'Shoucang/Shoucang.entitlements').read_bytes())['com.apple.security.application-groups'][0]
        # Signing identifiers only; no feature, source logic or extension is removed.
        text = text.replace('PRODUCT_BUNDLE_IDENTIFIER: com.shoucang.app.share', 'PRODUCT_BUNDLE_IDENTIFIER: ' + cfg['bundle_id'] + '.share')
        text = text.replace('PRODUCT_BUNDLE_IDENTIFIER: com.shoucang.app', 'PRODUCT_BUNDLE_IDENTIFIER: ' + cfg['bundle_id'])
        text = re.sub(r'CURRENT_PROJECT_VERSION: "[0-9]+"', 'CURRENT_PROJECT_VERSION: "' + os.environ['GITHUB_RUN_NUMBER'] + '"', text)
        spec_path.write_text(text, encoding='utf-8')
        for p in ios.rglob('*'):
            if p.suffix in ('.swift', '.entitlements', '.yml', '.xcconfig'):
                before = p.read_text(encoding='utf-8'); after = before.replace(old_group, cfg['app_group'])
                if before != after: p.write_text(after, encoding='utf-8')
        for f in ['app.xcconfig', 'share.xcconfig']: (ios / 'ci' / f).write_text('', encoding='utf-8')
        private_write(ROOT / 'AuthKey.p8', base64.b64decode(packet['asc_p8']))
        loaded, cert, chain = pkcs12.load_key_and_certificates(base64.b64decode(packet['p12']), packet['p12_password'].encode())
        if loaded is None or cert is None: raise ValueError('Signing identity missing')
        if cert.public_bytes(Encoding.DER) != base64.b64decode(cfg['certificate_der']): raise ValueError('Signing identity mismatch')
        private_write(pemkey, loaded.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
        private_write(pemcert, cert.public_bytes(Encoding.PEM))
        # A fresh ephemeral keychain, not a user keychain. User p12 password never enters argv or a file.
        kp = base64.urlsafe_b64encode(os.urandom(24)).decode()
        run_private(['security', 'create-keychain', '-p', kp, str(keychain)], 'keychain_create')
        run_private(['security', 'unlock-keychain', '-p', kp, str(keychain)], 'keychain_unlock')
        run_private(['security', 'import', str(pemkey), '-k', str(keychain), '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'], 'key_import')
        run_private(['security', 'import', str(pemcert), '-k', str(keychain)], 'certificate_import')
        pemkey.unlink(); pemcert.unlink()
        run_private(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:', '-s', '-k', kp, str(keychain)], 'keychain_partition')
        run_private(['security', 'list-keychains', '-d', 'user', '-s', str(keychain)], 'keychain_select')
        report['stages'].append('provided_distribution_identity_imported')
        run_private(['xcodebuild', '-version'], 'xcode_version')
        if not shutil.which('xcodegen'): run_private(['brew', 'install', 'xcodegen'], 'xcodegen_install', timeout=600)
        run_private(['xcodegen', 'generate'], 'generate_project', cwd=ios)
        archive = ROOT / 'Application.xcarchive'
        run_private(['xcodebuild', '-project', 'Shoucang.xcodeproj', '-scheme', 'Shoucang', '-configuration', 'Release', '-sdk', 'iphoneos', '-destination', 'generic/platform=iOS', '-archivePath', str(archive), 'CODE_SIGNING_ALLOWED=NO', 'archive'], 'archive', cwd=ios)
        report['stages'].append('real_device_archive_compiled')
        opts = {'method': cfg['export_method'], 'destination': 'export', 'teamID': cfg['team_id'], 'signingStyle': 'automatic', 'signingCertificate': 'Apple Distribution', 'stripSwiftSymbols': True, 'manageAppVersionAndBuildNumber': False}
        private_write(ROOT / 'ExportOptions.plist', plistlib.dumps(opts))
        run_private(['xcodebuild', '-exportArchive', '-archivePath', str(archive), '-exportOptionsPlist', str(ROOT / 'ExportOptions.plist'), '-exportPath', str(ROOT / 'export'), '-allowProvisioningUpdates', '-authenticationKeyPath', str(ROOT / 'AuthKey.p8'), '-authenticationKeyID', packet['asc_key_id'], '-authenticationKeyIssuerID', packet['asc_issuer_id']], 'export', timeout=600)
        ipas = list((ROOT / 'export').glob('*.ipa'))
        if len(ipas) != 1: raise ValueError('No unique exported IPA')
        report['bundle_validation'] = verify_ipa(ipas[0], cfg)
        report['ipa'] = {'filename': ipas[0].name, 'bytes': ipas[0].stat().st_size, 'sha256': hashlib.sha256(ipas[0].read_bytes()).hexdigest()}
        report['success'] = True
        print('A real signed IPA was produced and checked. Result is encrypted.')
    except BaseException as exc:
        report['failure'] = {'type': type(exc).__name__, 'stage_summary': str(exc)[:240]}
        print('The build did not satisfy the installation gate. Details are encrypted.')
        raise
    finally:
        report['ended_utc'] = datetime.now(timezone.utc).isoformat()
        private_write(ROOT / 'private_report.json', json.dumps(report, ensure_ascii=False, indent=2).encode())
        for p in [pemkey, pemcert, ROOT / 'AuthKey.p8']:
            if p.exists(): p.unlink()
        if keychain.exists():
            with (ROOT / 'cleanup.log').open('ab') as log: subprocess.run(['security', 'delete-keychain', str(keychain)], stdout=log, stderr=log, check=False)

def publish():
    # Only selected logs/report/IPA leave the runner, encrypted before any API call.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for p in sorted(ROOT.glob('*.log')) + sorted(ROOT.glob('private_report.json')) + sorted((ROOT / 'export').glob('*.ipa')):
            if p.is_file(): z.write(p, p.name)
    report_path = ROOT / 'private_report.json'
    success = json.loads(report_path.read_text())['success'] if report_path.exists() else False
    nonce = os.urandom(12); aad = (REPO + ':' + RUN_ID).encode()
    blob = b'QIFURS01' + nonce + AESGCM(key()).encrypt(nonce, buf.getvalue(), aad)
    if len(blob) >= 80 * 1024 * 1024: raise ValueError('Encrypted result exceeds bounded return size')
    manifest = {'format': 'QIFURS01', 'run_id': RUN_ID, 'success': success, 'encrypted_bytes': len(blob), 'encrypted_sha256': hashlib.sha256(blob).hexdigest(), 'application_source_public': False, 'plaintext_logs_public': False}
    token = os.environ['RESULT_GITHUB_TOKEN']
    def api(path, data):
        req = urllib.request.Request('https://api.github.com/repos/' + REPO + path, data=json.dumps(data).encode(), headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json', 'User-Agent': 'confidential-ios-ci'}, method='POST')
        with urllib.request.urlopen(req, timeout=40) as f: return json.load(f)
    entries = []
    for name, data in [('result.enc', blob), ('manifest.json', json.dumps(manifest, indent=2).encode())]:
        b = api('/git/blobs', {'encoding': 'base64', 'content': base64.b64encode(data).decode()})
        entries.append({'path': name, 'mode': '100644', 'type': 'blob', 'sha': b['sha']})
    tree = api('/git/trees', {'tree': entries})
    commit = api('/git/commits', {'message': 'Encrypted confidential iOS result ' + RUN_ID, 'tree': tree['sha'], 'parents': []})
    api('/git/refs', {'ref': 'refs/heads/result/' + RUN_ID, 'sha': commit['sha']})
    print('Encrypted result published to its unique result branch; no artifact-storage upload.')

if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('build', 'publish'): raise SystemExit('Specify build or publish')
    if sys.argv[1] == 'build': build()
    else: publish()
