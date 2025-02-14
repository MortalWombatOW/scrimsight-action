import * as github from '@actions/github';
import * as core from '@actions/core';

export async function postComment(token, body) {
  const octokit = github.getOctokit(token);
  const context = github.context;

  await octokit.rest.issues.createComment({
    ...context.repo,
    issue_number: context.issue.number,
    body
  });
} 