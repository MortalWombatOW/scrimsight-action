import * as github from '@actions/github';

export async function getPRDiff(githubToken, context) {
  const octokit = github.getOctokit(githubToken);
  
  try {
    const response = await octokit.pulls.get({
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