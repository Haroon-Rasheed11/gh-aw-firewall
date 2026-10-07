// eslint-disable-next-line @typescript-eslint/no-require-imports
jest.mock('execa', () => require('./test-helpers/mock-execa.test-utils').execaMockFactory());
jest.mock('./artifact-permissions', () => ({
  ...jest.requireActual<typeof import('./artifact-permissions')>('./artifact-permissions'),
  fixArtifactPermissionsForRootless: jest.fn().mockReturnValue(true),
}));

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import execa from 'execa';
import { preserveCleanupArtifacts } from './artifact-preservation';
import { fixArtifactPermissionsForRootless } from './artifact-permissions';
import { mockExecaSync } from './test-helpers/mock-execa.test-utils';
import { BoundedOutputCapture, writeGuestOutputAudit } from './cloud-hypervisor/diagnostics';
import { dependencies } from './cloud-hypervisor/manager.test-utils';

describe('Cloud Hypervisor diagnostic artifact handoff', () => {
  let scratch: string;
  const extraCleanup: string[] = [];

  beforeEach(() => {
    jest.clearAllMocks();
    scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'awf-private-diagnostics-'));
    const realExeca = jest.requireActual<typeof execa>('execa');
    mockExecaSync.mockImplementation((command: string, args: string[]) => {
      if (command !== 'chmod') throw new Error(`Unexpected command: ${command}`);
      return realExeca.sync(command, args);
    });
  });

  afterEach(() => {
    for (const directory of [scratch, ...extraCleanup.splice(0)]) {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

  it.each(['audit', 'audit-diagnostics', 'default-audit', 'default-diagnostics'])(
    'preserves runner-owned private diagnostics through %s cleanup',
    async (location) => {
      const runId = path.basename(scratch);
      const workDir = path.join(scratch, `awf-${runId}`);
      fs.mkdirSync(workDir);
      const auditDir = location.startsWith('audit') ? path.join(scratch, 'audit') : undefined;
      const container = location === 'audit' ? auditDir!
        : location === 'audit-diagnostics' || location === 'default-diagnostics'
          ? path.join(workDir, 'diagnostics')
          : path.join(workDir, 'audit');
      fs.mkdirSync(container, { recursive: true });
      const source = path.join(container, 'cloud-hypervisor');
      const identity = { uid: process.getuid!(), gid: process.getgid!() };
      const deps = dependencies({
        mkdir: fs.promises.mkdir,
        writeFile: fs.promises.writeFile,
        chmod: fs.promises.chmod,
        chown: jest.fn(fs.promises.chown),
        resolveIdentity: jest.fn().mockReturnValue(identity),
      });
      const capture = new BoundedOutputCapture(1024);
      capture.append('secret');
      await writeGuestOutputAudit(source, deps, capture, capture);
      const ordinary = path.join(container, 'ordinary.log');
      fs.writeFileSync(ordinary, 'public diagnostic', { mode: 0o600 });
      if (auditDir) fs.mkdirSync(auditDir, { recursive: true });

      preserveCleanupArtifacts(workDir, { auditDir });

      const destinationContainer = location === 'audit' ? auditDir!
        : location === 'audit-diagnostics' ? path.join(auditDir!, 'diagnostics')
          : path.join(os.tmpdir(), location === 'default-audit'
            ? `awf-audit-${runId}` : `awf-diagnostics-${runId}`);
      if (!auditDir) extraCleanup.push(destinationContainer);
      const destination = path.join(destinationContainer, 'cloud-hypervisor');
      const directoryStat = fs.statSync(destination);
      expect(directoryStat.mode & 0o777).toBe(0o700);
      expect(directoryStat.uid).toBe(identity.uid);
      expect(directoryStat.gid).toBe(identity.gid);
      for (const file of ['guest-stdout.raw.log', 'guest-stderr.raw.log']) {
        const filePath = path.join(destination, file);
        const stat = fs.statSync(filePath);
        expect(stat.mode & 0o777).toBe(0o600);
        expect(stat.uid).toBe(identity.uid);
        expect(stat.gid).toBe(identity.gid);
        expect(deps.chown).toHaveBeenCalledWith(path.join(source, file), identity.uid, identity.gid);
        fs.writeFileSync(filePath, '[REDACTED]');
        fs.unlinkSync(filePath);
      }
      expect(fs.statSync(path.join(destinationContainer, 'ordinary.log')).mode & 0o777).toBe(0o644);
      const repairDirectories = jest.mocked(fixArtifactPermissionsForRootless).mock.calls[0][0];
      if (auditDir) expect(repairDirectories).not.toContain(auditDir);
      expect(repairDirectories).not.toContain(destination);
      expect(repairDirectories).not.toContain(path.dirname(destination));
    },
  );
});
