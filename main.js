import { getExecDiff } from './diff.js';
import { analyzeWithGemini } from './analyzer.js';
import { postComment } from './github.js';
import * as core from '@actions/core';

async function run() {
  try {
    const prDiff = await getExecDiff();
    const standards = JSON.parse(core.getInput('standards'));
    
    let commentBody = "## Scrimsight Code Review Results\n\n";
    
    for (const standard of standards) {
      const analysis = await analyzeWithGemini(
        core.getInput('gemini-api-key'),
        standard,
        prDiff
      );
      
      commentBody += `### Standard: ${standard}\n`;
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