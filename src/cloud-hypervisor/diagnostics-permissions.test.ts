import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  BoundedOutputCapture,
  collectCloudHypervisorDiagnostics,
  preserveVirtiofsdStartupEvidence,
  writeGuestOutputAudit,
} from './diagnostics';
import { createCloudHypervisorRunPaths } from './manager-types';
import { config, dependencies } from './manager.test-utils';

describe('Cloud Hypervisor diagnostic ownership', () => {
  let scratch: string;

  beforeEach(async () => {
    scratch = await fs.mkdtemp(path.join(os.tmpdir(), 'awf-ch-audit-'));
  });

  afterEach(async () => {
    await fs.rm(scratch, { recursive: true, force: true });
  });

  it.each(['full diagnostics', 'guest output audit'])(
    'hands off %s with runner ownership and private modes, including existing files',
    async (collection) => {
      const directory = path.join(scratch, 'cloud-hypervisor');
      await fs.mkdir(directory, { mode: 0o755 });
      await fs.writeFile(path.join(directory, 'guest-stdout.raw.log'), 'old', { mode: 0o644 });
      const identity = { uid: 1234, gid: 2345 };
      const deps = dependencies({
        mkdir: fs.mkdir,
        writeFile: fs.writeFile,
        chmod: jest.fn(fs.chmod),
        chown: jest.fn().mockResolvedValue(undefined),
        resolveIdentity: jest.fn().mockReturnValue(identity),
      });
      const capture = new BoundedOutputCapture(1024);
      capture.append('private output');
      if (collection === 'guest output audit') {
        await writeGuestOutputAudit(directory, deps, capture, capture);
      } else {
        await collectCloudHypervisorDiagnostics(directory, {
          dependencies: deps,
          paths: createCloudHypervisorRunPaths('/opt/cloud-hypervisor', 'permissions'),
          config: config(),
          stdoutCapture: capture,
          stderrCapture: capture,
          guestStdoutCapture: capture,
          guestStderrCapture: capture,
          network: undefined,
          networkPlan: undefined,
          client: undefined,
          instanceStarted: false,
          lastVmInfo: undefined,
          lastVmCounters: undefined,
          fsDevices: [{
            export: { tag: 'workspace', source: '/workspace', target: '/workspace', mode: 'rw' },
            socketPath: '/unused.sock',
            logPath: '/virtiofs.log',
            evidencePath: '/virtiofs-confinement.json',
          }],
          confinementEvidence: undefined,
        });
      }

      expect(deps.resolveIdentity).toHaveBeenCalledTimes(1);
      expect(deps.chown).toHaveBeenCalledWith(directory, identity.uid, identity.gid);
      expect((await fs.stat(directory)).mode & 0o777).toBe(0o700);
      const files = await fs.readdir(directory);
      expect(files).toEqual(expect.arrayContaining([
        'guest-stdout.raw.log', 'guest-stderr.raw.log',
      ]));
      if (collection === 'full diagnostics') {
        expect(files).toEqual(expect.arrayContaining([
          'launcher-stdout.log', 'launcher-stderr.log', 'cloud-hypervisor.log',
          'serial.log', 'virtiofs-0-workspace.log', 'virtiofs-0-workspace-confinement.json',
          'network-plan.json', 'network-diagnostics.txt', 'counters.json',
          'vm-info.json', 'runtime.json', 'confinement.json',
        ]));
      }
      for (const file of files) {
        const destination = path.join(directory, file);
        expect(deps.chown).toHaveBeenCalledWith(destination, identity.uid, identity.gid);
        expect(deps.chmod).toHaveBeenCalledWith(destination, 0o600);
        expect((await fs.stat(destination)).mode & 0o777).toBe(0o600);
      }
      expect(deps.chown).toHaveBeenCalledTimes(files.length + 1);
    },
  );

  it('makes the diagnostic root runner-owned when a boot-attempt directory is created first', async () => {
    const root = path.join(scratch, 'cloud-hypervisor');
    const directory = path.join(root, 'boot-attempt-1');
    const deps = dependencies({
      mkdir: fs.mkdir,
      writeFile: fs.writeFile,
      chmod: fs.chmod,
      chown: jest.fn().mockResolvedValue(undefined),
    });
    const capture = new BoundedOutputCapture(1024);
    await writeGuestOutputAudit(directory, deps, capture, capture);
    expect(deps.chown).toHaveBeenCalledWith(root, 1000, 1000);
    expect(deps.chown).toHaveBeenCalledWith(directory, 1000, 1000);
    expect((await fs.stat(root)).mode & 0o777).toBe(0o700);
  });

  it('propagates ownership repair failure instead of reporting a successful handoff', async () => {
    const deps = dependencies({
      chown: jest.fn().mockRejectedValue(Object.assign(new Error('ownership denied'), { code: 'EPERM' })),
    });
    const capture = new BoundedOutputCapture(1024);
    await expect(writeGuestOutputAudit(scratch, deps, capture, capture))
      .rejects.toThrow('ownership denied');
    expect(deps.writeFile).not.toHaveBeenCalled();
  });

  it('hands off startup evidence with private modes and a runner-owned diagnostic root', async () => {
    const evidence = path.join(scratch, 'evidence.json');
    await fs.writeFile(evidence, '{}', { mode: 0o644 });
    const root = path.join(scratch, 'cloud-hypervisor');
    const directory = path.join(root, 'startup-run');
    const deps = dependencies({
      mkdir: fs.mkdir,
      copyFile: fs.copyFile,
      chmod: fs.chmod,
      chown: jest.fn().mockResolvedValue(undefined),
    });
    await preserveVirtiofsdStartupEvidence(deps, [{
      export: { tag: 'workspace', source: '/workspace', target: '/workspace', mode: 'rw' },
      socketPath: '/unused.sock',
      logPath: '/unused.log',
      evidencePath: evidence,
    }], directory);
    expect(deps.chown).toHaveBeenCalledWith(root, 1000, 1000);
    expect(deps.chown).toHaveBeenCalledWith(directory, 1000, 1000);
    const destination = path.join(directory, 'evidence.json');
    expect(deps.chown).toHaveBeenCalledWith(destination, 1000, 1000);
    expect((await fs.stat(directory)).mode & 0o777).toBe(0o700);
    expect((await fs.stat(destination)).mode & 0o777).toBe(0o600);
  });
});
