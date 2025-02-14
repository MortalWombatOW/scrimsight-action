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