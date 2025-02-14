import * as github from '@actions/github';
import * as core from '@actions/core';

export async function postComment(body) {
  const octokit = github.getOctokit(process.env.GITHUB_TOKEN);
  const context = github.context;

  await octokit.rest.issues.createComment({
    ...context.repo,
    issue_number: context.issue.number,
    body
  });
} 