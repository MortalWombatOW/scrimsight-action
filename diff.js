import { exec } from 'child_process';
import { promisify } from 'util';

export async function getExecDiff() {
  const execPromise = promisify(exec);
  const { stdout } = await execPromise(
    'git diff --unified=0 HEAD^ HEAD'
  );
  return stdout;
} 