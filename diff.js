import * as github from '@actions/github';
import { Octokit } from "octokit";

export async function getPRDiff(githubToken, context) {
  const octokit = new Octokit({ auth: githubToken });
  
  try {
    const response = await octokit.rest.pulls.get({
      owner: context.repo.owner,
      repo: context.repo.repo,
      pull_number: context.issue.number,
      mediaType: { format: 'diff' }
    });
    
    // @ts-ignore - response.data is string when using diff format
    return response.data;
  } catch (error) {
    throw new Error(`Failed to get PR diff: ${error.message}`);
  }
}

export function filterDiffByFileTypes(diff, extensions) {
  if (!diff) return '';
  const tsPattern = new RegExp(`\\.(${extensions.join('|')})$`);
  
  return diff.split('\n').reduce((acc, line) => {
    if (line.startsWith('diff --git')) {
      const isTargetFile = tsPattern.test(line);
      acc.include = isTargetFile;
      if (isTargetFile) acc.result += '\n'; // Preserve spacing between diffs
    }
    
    if (acc.include) {
      acc.result += line + '\n';
    }
    
    return acc;
  }, { result: '', include: false }).result.trim();
} 