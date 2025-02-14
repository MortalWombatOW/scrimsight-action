import { GoogleGenerativeAI } from "@google/generative-ai";

export async function analyzeWithGemini(apiKey, standard, diff) {
  const genAI = new GoogleGenerativeAI(apiKey);
  const model = genAI.getGenerativeModel({ 
    model: "gemini-1.5-flash",
    systemInstruction: `Analyze code changes against this standard: ${standard.shortname} - ${standard.description}.
      Use these examples to guide your analysis:
      Good Example:
      \`\`\`${standard.positiveExample}\`\`\`
      
      Bad Example:
      \`\`\`${standard.negativeExample}\`\`\`
      
      Respond in format: "${standard.shortname}: [PASSED/FAILED]\nLines [X-Y]: [Explanation]"`
  });

  try {
    const result = await model.generateContent([
      `Code diff:\n${diff}\n\nAssessment:`,
    ]);
    
    const response = await result.response.text();
    return parseGeminiResponse(response);
  } catch (error) {
    throw new Error(`Gemini API error: ${error.message}`);
  }
}

function parseGeminiResponse(response) {
  const lines = response.split('\n');
  const result = {
    standardName: '',
    foundIssues: false,
    details: []
  };

  lines.forEach(line => {
    const match = line.match(/(.*?):\s*(PASSED|FAILED)/);
    if (match) {
      result.standardName = match[1];
      result.foundIssues = match[2] === 'FAILED';
    } else if (line.startsWith('Lines')) {
      result.details.push(line);
    }
  });

  return {
    foundIssues: result.foundIssues,
    details: result.details.join('\n')
  };
} 