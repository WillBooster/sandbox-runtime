import path from 'node:path';

const directory = import.meta.dir;
for (const [name, target] of [
  ['arm64', 'aarch64-linux-musl'],
  ['x64', 'x86_64-linux-musl'],
]) {
  const process = Bun.spawn(
    [
      'zig',
      'cc',
      '-target',
      target!,
      '-static',
      '-O2',
      '-s',
      '-pthread',
      '-Wall',
      '-Wextra',
      '-I',
      directory,
      path.resolve(directory, '../../vendor/seccomp-src/apply-seccomp.c'),
      '-o',
      path.join(directory, `${name}.bin`),
    ],
    { stdout: 'inherit', stderr: 'inherit' }
  );
  if ((await process.exited) !== 0) throw new Error(`Failed to build SSH-agent supervisor for ${name}`);
}
