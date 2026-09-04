const { spawn } = require('child_process');
const path = require('path');

/**
 * Executes the Python URL intelligence analyzer for a list of URLs and sender email.
 * @param {Array<string>} urls - List of extracted link URLs
 * @param {string} senderEmail - Sender's From email address
 * @returns {Promise<Object>} Analyzed URL intelligence payload
 */
function analyzeUrls(urls, senderEmail = '') {
  return new Promise((resolve, reject) => {
    if (!urls || urls.length === 0) {
      return resolve({
        summary: {
          total_urls: 0,
          critical_risk_urls: 0,
          high_risk_urls: 0,
          medium_risk_urls: 0,
          low_risk_urls: 0,
          max_risk_score: 0,
          overall_status: 'LOW'
        },
        urls: []
      });
    }

    // Path to the root Python virtual environment
    const isWindows = process.platform === 'win32';
    const pythonExecutable = isWindows
      ? path.resolve(__dirname, '../../.venv/Scripts/python.exe')
      : path.resolve(__dirname, '../../.venv/bin/python');

    const projectRoot = path.resolve(__dirname, '../../');

    const pythonScript = `
import sys
import json
from url_intelligence import analyze_urls

input_data = json.loads(sys.stdin.read())
urls = input_data.get('urls', [])
sender = input_data.get('sender', '')

report = analyze_urls(urls, sender_email=sender)
print(json.dumps(report))
`;

    const pyProcess = spawn(pythonExecutable, ['-c', pythonScript], {
      cwd: projectRoot
    });

    let stdoutData = '';
    let stderrData = '';

    pyProcess.stdin.write(JSON.stringify({ urls, sender: senderEmail }));
    pyProcess.stdin.end();

    pyProcess.stdout.on('data', (chunk) => {
      stdoutData += chunk.toString();
    });

    pyProcess.stderr.on('data', (chunk) => {
      stderrData += chunk.toString();
    });

    pyProcess.on('close', (code) => {
      if (code !== 0) {
        return reject(new Error(`URL Intelligence failed (code ${code}): ${stderrData}`));
      }
      try {
        const result = JSON.parse(stdoutData.trim());
        resolve(result);
      } catch (err) {
        reject(new Error(`Failed to parse URL intelligence output: ${err.message}`));
      }
    });
  });
}

module.exports = {
  analyzeUrls
};