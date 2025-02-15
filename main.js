import { getPRDiff, filterDiffByFileTypes } from './diff.js';
import { analyzeWithGemini } from './analyzer.js';
import { postComment } from './github.js';
import * as core from '@actions/core';
import * as github from '@actions/github';

async function run() {
  try {
    const githubToken = core.getInput('github-token');
    const context = github.context;
    
    const prDiff = await getPRDiff(githubToken, context);
    const tsDiff = filterDiffByFileTypes(prDiff, ['ts', 'tsx']);
    const standards = JSON.parse(core.getInput('standards'));
    
    let commentBody = "## Scrimsight Code Review Results\n\n";
    
    for (const standard of standards) {
      const analysis = await analyzeWithGemini(
        core.getInput('gemini-api-key'),
        standard,
        tsDiff
      );
      
      commentBody += `### ${standard.shortname}\n`;
      commentBody += `_${standard.description}_\n\n`;
      commentBody += analysis.foundIssues 
        ? `⚠️ **Issues Found**\n${analysis.details}\n`
        : "✅ All checks passed\n";
      commentBody += "\n";
    }

    await postComment(commentBody);
  } catch (error) {
    console.error(error);
    core.setFailed(error.message);
  }
}

run(); 